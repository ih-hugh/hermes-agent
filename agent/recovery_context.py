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
_ACTIVE_STORE: ContextVar[tuple[int, int] | None] = ContextVar("recovery_store_writer", default=None)
_ACTIVE_USAGE_APPLY: ContextVar[tuple[int, int, int] | None] = ContextVar(
    "recovery_usage_apply", default=None)
_ACTIVE_GENERIC_WRITE: ContextVar[tuple[int, int, int] | None] = ContextVar(
    "recovery_generic_write", default=None)


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


def write_binding(permit: WritePermit, store: RecoveryStore) -> tuple[RecoveryScope, str, int] | None:
    """Return a process-owned generic permit identity without granting SQL authority."""
    if type(permit) is not WritePermit or usage_write_binding(permit, store) is not None:
        return None
    try:
        record = _REGISTRY.get(permit)
    except TypeError:
        return None
    if record is None or record[:3] != (os.getpid(), _PROCESS_NONCE, id(store.db)):
        return None
    scope, run_id, generation = record[3:]
    if scope.store_id != store.store_id:
        return None
    return scope, run_id, generation


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
    phase = store.db._read_one("SELECT phase FROM recovery_sessions WHERE session_id=?", (scope.session_id,))
    if phase is None or phase[0] != "open":
        raise RecoveryRefused("session_closing")
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


@contextmanager
def _store_writer(db: object, conn: object) -> Iterator[None]:
    """RecoveryStore's private authority, scoped to one callback and connection."""
    token = _ACTIVE_STORE.set((id(db), id(conn)))
    try:
        yield
    finally:
        _ACTIVE_STORE.reset(token)


def authorize_recovery_store(db: object, conn: object) -> bool:
    return _ACTIVE_STORE.get() == (id(db), id(conn))


def authorize_recovery_row(db: object, conn: object, session_id: str | None,
                           mutation: str) -> bool:
    """Read the live member and slot on this connection inside the protected write."""
    if not session_id:
        return False
    session = conn.execute(
        "SELECT profile,scope_digest,phase FROM recovery_sessions WHERE session_id=?",
        (session_id,),
    ).fetchone()
    if session is None:
        return True
    permit = _ACTIVE_WRITE.get()
    if type(permit) is not WritePermit:
        return False
    try:
        record = _REGISTRY.get(permit)
    except TypeError:
        return False
    if record is None:
        return False
    pid, nonce, db_id, scope, run_id, generation = record
    if ((pid, nonce, db_id) != (os.getpid(), _PROCESS_NONCE, id(db))
            or scope.session_id != session_id or scope.profile != session[0]
            or scope.scope_digest != session[1] or session[2] not in {"open", "closing"}):
        return False
    member = conn.execute(
        "SELECT owner_incarnation,producer_state FROM recovery_members "
        "WHERE run_id=? AND session_id=? AND generation=? AND profile=? AND scope_digest=?",
        (run_id, session_id, generation, scope.profile, scope.scope_digest),
    ).fetchone()
    if member is None or member[0] != current_incarnation() or member[1] != "open":
        return False
    usage = _USAGE_WRITES.get(permit)
    if usage is None:
        if mutation == "message":
            return _ACTIVE_GENERIC_WRITE.get() == (id(db), id(conn), id(permit))
        return mutation in {"session", "completion"}
    if mutation not in {"usage", "session"}:
        return False
    if _ACTIVE_USAGE_APPLY.get() != (id(db), id(conn), id(permit)):
        return False
    _, _, usage_db_id, store_id, usage_scope, usage_run_id, usage_generation, producer_id, attempt_id, delta_id = usage
    if ((usage_db_id, store_id, usage_scope, usage_run_id, usage_generation)
            != (id(db), scope.store_id, scope, run_id, generation)):
        return False
    slot = conn.execute(
        "SELECT s.state,a.state,p.state,p.owner_incarnation "
        "FROM recovery_usage_slots s JOIN recovery_sends a USING(attempt_id) "
        "JOIN recovery_producers p ON p.producer_id=a.producer_id "
        "WHERE s.delta_id=? AND s.attempt_id=? AND a.run_id=? AND a.producer_id=?",
        (delta_id, attempt_id, run_id, producer_id),
    ).fetchone()
    return bool(slot and slot[0] == "pending" and slot[1] == "invoking"
                and slot[2] in {"running", "closed"} and slot[3] == current_incarnation())


@contextmanager
def _usage_apply(db: object, conn: object, permit: WritePermit) -> Iterator[None]:
    token = _ACTIVE_USAGE_APPLY.set((id(db), id(conn), id(permit)))
    try:
        with bind_write_permit(permit):
            yield
    finally:
        _ACTIVE_USAGE_APPLY.reset(token)


@contextmanager
def _generic_write(db: object, conn: object, permit: WritePermit) -> Iterator[None]:
    token = _ACTIVE_GENERIC_WRITE.set((id(db), id(conn), id(permit)))
    try:
        with bind_write_permit(permit):
            yield
    finally:
        _ACTIVE_GENERIC_WRITE.reset(token)
