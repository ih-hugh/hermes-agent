"""Process-owned, non-serializable permits for protected producers and writes."""

from __future__ import annotations

import os
import threading
import uuid
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore


_PROCESS_NONCE = uuid.uuid4().hex
_ISSUER = object()
_REGISTRY: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
_HANDOFFS: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
_ISSUE_LOCK = threading.Lock()
_ACTIVE_WRITE: ContextVar[WritePermit | None] = ContextVar("recovery_write_permit", default=None)


def current_incarnation() -> str:
    return f"{os.getpid()}:{_PROCESS_NONCE}"


class ProducerPermit:
    __slots__ = ("__weakref__",)

    def __init__(self, issuer: object):
        if issuer is not _ISSUER:
            raise TypeError("producer permits are issued internally")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("producer permits cannot be copied or serialized")


class WritePermit:
    __slots__ = ("__weakref__",)

    def __init__(self, issuer: object):
        if issuer is not _ISSUER:
            raise TypeError("write permits are issued internally")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("write permits cannot be copied or serialized")


class AdmissionHandoff:
    """One-use authority returned only with a newly committed reservation."""

    __slots__ = ("__weakref__",)

    def __init__(self, issuer: object):
        if issuer is not _ISSUER:
            raise TypeError("admission handoffs are issued internally")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("admission handoffs cannot be copied or serialized")


def _register_admission_handoff(store: RecoveryStore, identity: AdmissionIdentity,
                                generation: int) -> AdmissionHandoff | None:
    """Called by RecoveryStore only after its BEGIN IMMEDIATE reservation committed."""
    if identity.owner_incarnation != current_incarnation():
        return None
    handoff = AdmissionHandoff(_ISSUER)
    with _ISSUE_LOCK:
        _HANDOFFS[handoff] = (
            os.getpid(), _PROCESS_NONCE, id(store.db), store.store_id, identity.scope,
            identity.run_id, generation, identity.idempotency_key, identity.request_sha256,
            identity.owner_incarnation)
    return handoff


def issue_producer_permit(store: RecoveryStore, handoff: AdmissionHandoff) -> ProducerPermit:
    from hermes_state_recovery import RecoveryRefused

    if type(handoff) is not AdmissionHandoff:
        raise RecoveryRefused("invalid_admission_handoff")
    with _ISSUE_LOCK:
        record = _HANDOFFS.pop(handoff, None)
    if record is None:
        raise RecoveryRefused("admission_handoff_consumed")
    (pid, nonce, db_id, store_id, scope, run_id, generation, key, fingerprint, owner) = record
    if (pid, nonce, db_id, store_id) != (os.getpid(), _PROCESS_NONCE, id(store.db), store.store_id):
        raise RecoveryRefused("foreign_producer")
    row = store.db._read_one(
        "SELECT generation,owner_incarnation,producer_state,idempotency_key,request_sha256 "
        "FROM recovery_members "
        "WHERE run_id=? AND session_id=? AND profile=? AND scope_digest=?",
        (run_id, scope.session_id, scope.profile, scope.scope_digest))
    if (row is None or (row[0], row[1], row[2], row[3], row[4])
            != (generation, owner, "open", key, fingerprint) or owner != current_incarnation()):
        raise RecoveryRefused("admission_handoff_mismatch")
    with _ISSUE_LOCK:
        permit = ProducerPermit(_ISSUER)
        _REGISTRY[permit] = (os.getpid(), _PROCESS_NONCE, id(store.db), scope,
                             run_id, generation)
    return permit


def validate_producer_permit(permit: ProducerPermit, store: RecoveryStore, scope: RecoveryScope,
                             run_id: str, generation: int) -> bool:
    return _validate_permit(permit, ProducerPermit, store, scope, run_id, generation)


def _validate_permit(permit: object, kind: type, store: RecoveryStore, scope: RecoveryScope,
                     run_id: str, generation: int) -> bool:
    if type(permit) is not kind:
        return False
    try:
        record = _REGISTRY.get(permit)
    except TypeError:
        return False
    if record != (os.getpid(), _PROCESS_NONCE, id(store.db), scope, run_id, generation):
        return False
    row = store.db._read_one(
        "SELECT owner_incarnation,producer_state FROM recovery_members WHERE run_id=? AND session_id=?",
        (run_id, scope.session_id))
    return bool(row and row[0] == current_incarnation() and row[1] == "open")


def issue_write_permit(permit: ProducerPermit, store: RecoveryStore, scope: RecoveryScope,
                       run_id: str, generation: int) -> WritePermit:
    from hermes_state_recovery import RecoveryRefused

    if not validate_producer_permit(permit, store, scope, run_id, generation):
        raise RecoveryRefused("invalid_producer_permit")
    issued = WritePermit(_ISSUER)
    _REGISTRY[issued] = (os.getpid(), _PROCESS_NONCE, id(store.db), scope, run_id, generation)
    return issued


def validate_write_permit(permit: WritePermit, store: RecoveryStore, scope: RecoveryScope,
                          run_id: str, generation: int) -> bool:
    return _validate_permit(permit, WritePermit, store, scope, run_id, generation)


@contextmanager
def bind_write_permit(permit: WritePermit) -> Iterator[None]:
    token = _ACTIVE_WRITE.set(permit)
    try:
        yield
    finally:
        _ACTIVE_WRITE.reset(token)


def current_write_permit() -> WritePermit | None:
    return _ACTIVE_WRITE.get()
