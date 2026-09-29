"""Process-owned, non-serializable permits for protected producers and writes."""

from __future__ import annotations

import os
import threading
import uuid
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore


_PROCESS_NONCE = uuid.uuid4().hex
_ISSUER = object()
_REGISTRY: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
_HANDOFFS: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
_USAGE_COMPLETIONS: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
_USAGE_WRITES: weakref.WeakKeyDictionary[object, tuple] = weakref.WeakKeyDictionary()
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


class UsageCompletion:
    """One-use authority for the usage slot registered before one physical SDK send."""

    __slots__ = ("__weakref__",)

    def __init__(self, issuer: object):
        if issuer is not _ISSUER:
            raise TypeError("usage completions are issued internally")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("usage completions cannot be copied or serialized")


def _register_usage_completion(store: RecoveryStore, scope: RecoveryScope, run_id: str,
                               generation: int, producer_id: str, attempt_id: str,
                               delta_id: str) -> UsageCompletion:
    """Called only after SendLedger.begin durably registered this exact slot."""
    completion = UsageCompletion(_ISSUER)
    with _ISSUE_LOCK:
        _USAGE_COMPLETIONS[completion] = (
            os.getpid(), _PROCESS_NONCE, id(store.db), store.store_id, scope,
            run_id, generation, producer_id, attempt_id, delta_id)
    return completion


def issue_usage_write_permit(store: RecoveryStore, completion: UsageCompletion) -> WritePermit:
    """Consume one exact pre-send completion slot; the resulting permit supports idempotent retries."""
    from hermes_state_recovery import RecoveryRefused

    if type(completion) is not UsageCompletion:
        raise RecoveryRefused("invalid_usage_completion")
    with _ISSUE_LOCK:
        binding = _USAGE_COMPLETIONS.pop(completion, None)
    if binding is None:
        raise RecoveryRefused("usage_completion_consumed")
    pid, nonce, db_id, store_id, scope, run_id, generation, producer_id, attempt_id, delta_id = binding
    if (pid, nonce, db_id, store_id) != (os.getpid(), _PROCESS_NONCE, id(store.db), store.store_id):
        raise RecoveryRefused("foreign_usage_completion")
    row = store.db._read_one(
        "SELECT a.producer_id,s.state,m.owner_incarnation,m.producer_state,a.state "
        "FROM recovery_usage_slots s JOIN recovery_sends a USING(attempt_id) "
        "JOIN recovery_members m ON m.run_id=a.run_id "
        "WHERE s.delta_id=? AND s.attempt_id=? AND a.run_id=?",
        (delta_id, attempt_id, run_id))
    if (row is None or row[0] != producer_id or row[1] != "pending" or
            row[2] != current_incarnation() or row[3] != "open" or row[4] != "invoking"):
        raise RecoveryRefused("invalid_usage_completion")
    permit = WritePermit(_ISSUER)
    with _ISSUE_LOCK:
        _REGISTRY[permit] = (os.getpid(), _PROCESS_NONCE, id(store.db), scope, run_id, generation)
        _USAGE_WRITES[permit] = binding
    return permit


@dataclass(frozen=True, slots=True)
class UsageWriteBinding:
    scope: RecoveryScope
    run_id: str
    generation: int
    producer_id: str
    attempt_id: str
    delta_id: str
    mutation: str = "usage"


def usage_write_binding(permit: WritePermit, store: RecoveryStore) -> UsageWriteBinding | None:
    """Return exact pre-send authority for Task 3's guarded usage writer."""
    if type(permit) is not WritePermit:
        return None
    try:
        binding = _USAGE_WRITES.get(permit)
    except TypeError:
        return None
    if binding is None or binding[:4] != (os.getpid(), _PROCESS_NONCE, id(store.db), store.store_id):
        return None
    _, _, _, _, scope, run_id, generation, producer_id, attempt_id, delta_id = binding
    return UsageWriteBinding(scope, run_id, generation, producer_id, attempt_id, delta_id)


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
                          run_id: str, generation: int, *, mutation: str | None = None) -> bool:
    if not _validate_permit(permit, WritePermit, store, scope, run_id, generation):
        return False
    usage = usage_write_binding(permit, store)
    if usage is not None:
        return mutation == "usage" and usage.scope == scope and usage.run_id == run_id
    return mutation != "usage"


@contextmanager
def bind_write_permit(permit: WritePermit) -> Iterator[None]:
    token = _ACTIVE_WRITE.set(permit)
    try:
        yield
    finally:
        _ACTIVE_WRITE.reset(token)


def current_write_permit() -> WritePermit | None:
    return _ACTIVE_WRITE.get()
