"""Bounded, durable provider association and physical invocation inventory.

This is an internal authority for already protected sessions. It never claims a
workspace is quiescent or that a sealed receipt is ready.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Literal, Never, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gateway.platforms.api_server_recovery_artifacts import canonical_json_bytes
from gateway.platforms.api_server_recovery_contract import WorkspaceRefWire
from hermes_state_recovery import RecoveryRefused, RecoveryScope

if TYPE_CHECKING:
    import sqlite3
    from hermes_state_recovery import RecoveryStore


MAX_ADMISSION_BYTES = 4096
MAX_INVOCATIONS = 16_384
_ISSUER = object()
_LOCK = threading.Lock()
_CAPABILITIES: weakref.WeakKeyDictionary[ProviderInvocationPermit, tuple] = weakref.WeakKeyDictionary()
_PROCESS_NONCE = uuid.uuid4().hex


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProviderAdmissionValue(_Strict):
    provider: Literal["byf_workspace"]
    session_id: str = Field(min_length=1, max_length=255)
    hermes_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: WorkspaceRefWire

    @model_validator(mode="after")
    def _reference_matches(self) -> ProviderAdmissionValue:
        if self.reference.provider_sha256 != self.provider_sha256:
            raise ValueError("provider digest conflicts with reference")
        return self

    def canonical_bytes(self) -> bytes:
        value = canonical_json_bytes(self.model_dump(mode="json"))
        if len(value) > MAX_ADMISSION_BYTES:
            raise RecoveryRefused("provider_admission_oversized")
        return value


@dataclass(frozen=True, slots=True)
class ProviderInvocationOutcome:
    state: Literal["returned", "unknown"]
    container_id: str | None = None
    container_attestation_sha256: str | None = None
    exit_code: int | None = None
    reason: Literal["provider_exception", "lost_result"] | None = None

    def __post_init__(self) -> None:
        if self.state == "unknown":
            if (self.reason not in {"provider_exception", "lost_result"}
                    or self.container_id is not None
                    or self.container_attestation_sha256 is not None
                    or self.exit_code is not None):
                raise ValueError("invalid unknown provider outcome")
            return
        if self.state != "returned" or self.reason is not None:
            raise ValueError("invalid provider outcome")
        if self.container_id is not None and (
                type(self.container_id) is not str or not self.container_id
                or len(self.container_id) > 255):
            raise ValueError("invalid container ID")
        if self.container_attestation_sha256 is not None and (
                type(self.container_attestation_sha256) is not str
                or len(self.container_attestation_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.container_attestation_sha256)):
            raise ValueError("invalid container attestation")
        if self.exit_code is not None and (
                type(self.exit_code) is not int or not -(2**31) <= self.exit_code < 2**31):
            raise ValueError("invalid exit code")


class ProviderInvocationRow(_Strict):
    invocation_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    generation: Literal[0, 1]
    producer_id: str = Field(min_length=1, max_length=64)
    sequence: int = Field(ge=0, lt=MAX_INVOCATIONS)
    kind: Literal["create_environment", "execute"]
    state: Literal["invoking", "returned", "unknown"]
    create_invocation_id: str | None = Field(default=None, max_length=64)
    container_id: str | None = Field(default=None, max_length=255)
    container_attestation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    exit_code: int | None = Field(default=None, ge=-(2**31), lt=2**31)
    outcome_reason: Literal["provider_exception", "lost_result"] | None = None


class ProviderInvocationPermit:
    """One process-owned capability issued only after an invoking row commits."""

    __slots__ = ("__weakref__", "_invocation_id")

    def __init__(self, issuer: object, invocation_id: str):
        if issuer is not _ISSUER:
            raise TypeError("provider permits are issued internally")
        self._invocation_id = invocation_id

    @property
    def invocation_id(self) -> str:
        return self._invocation_id

    def __reduce_ex__(self, protocol: SupportsIndex, /) -> Never:
        raise TypeError("provider permits cannot be serialized")


@dataclass(frozen=True, slots=True)
class SelectedProviderCapture:
    """Process-local association with the exact plugin object that attested admission."""

    admission: ProviderAdmissionValue
    provider: object = field(repr=False, compare=False)

    def require_selected(self) -> object:
        from tools.terminal_tool import _get_env_config
        from tools.terminal_tool_config import _get_plugin_env_provider

        if (_get_env_config().get("env_type") != "byf_workspace"
                or _get_plugin_env_provider("byf_workspace") is not self.provider):
            raise RecoveryRefused("provider_selection_changed")
        return self.provider


def capture_selected_provider_admission(session_id: str) -> SelectedProviderCapture:
    """Inspect the terminal backend selected by the active profile, then capture it."""
    from tools.terminal_tool import _get_env_config
    from tools.terminal_tool_config import _get_plugin_env_provider
    from agent.terminal_env_provider import TerminalEnvironmentProvider

    try:
        config = _get_env_config()
        if config.get("env_type") != "byf_workspace":
            raise RecoveryRefused("unsupported_provider")
        provider = _get_plugin_env_provider("byf_workspace")
        if (not isinstance(provider, TerminalEnvironmentProvider)
                or type(provider).__name__ != "ByfWorkspaceProvider"
                or type(provider).__module__.split(".")[-1] != "byf_workspace"
                or getattr(provider, "name", None) != "byf_workspace"):
            raise RecoveryRefused("unsupported_provider")
        capture = getattr(provider, "capture_recovery_admission", None)
        if not callable(capture):
            raise RecoveryRefused("unsupported_provider")
        raw = capture(session_id)
        # The selected plugin returns the F strict DTO. Its own capture verifies
        # installed source, imported Hermes pin and the active signed grant.
        if (type(raw).__name__ != "RecoveryProviderAdmission"
                or type(raw).__module__.split(".")[-1] != "workspace_recovery"):
            raise RecoveryRefused("provider_admission_invalid")
        value = ProviderAdmissionValue.model_validate(raw.model_dump(mode="json"))
        if value.session_id != session_id:
            raise RecoveryRefused("provider_admission_invalid")
        value.canonical_bytes()
        return SelectedProviderCapture(value, provider)
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("provider_admission_invalid") from exc


def insert_admission(conn: sqlite3.Connection, value: ProviderAdmissionValue) -> None:
    payload = value.canonical_bytes()
    conn.execute(
        "INSERT INTO recovery_provider_admissions"
        "(session_id,provider,hermes_revision,source_sha256,provider_sha256,lease_id,"
        "grant_sha256,admission_json,admission_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
        (value.session_id, value.provider, value.hermes_revision, value.source_sha256,
         value.provider_sha256, value.reference.lease_id, value.reference.grant_sha256,
         payload, hashlib.sha256(payload).hexdigest()),
    )


def read_admission(conn: sqlite3.Connection, session_id: str) -> ProviderAdmissionValue:
    meta = conn.execute(
        "SELECT length(admission_json),typeof(admission_json),length(provider),"
        "length(hermes_revision),length(source_sha256),length(provider_sha256),"
        "length(lease_id),length(grant_sha256),length(admission_sha256) "
        "FROM recovery_provider_admissions "
        "WHERE session_id=?", (session_id,)).fetchone()
    if meta is None:
        raise RecoveryRefused("provider_admission_missing")
    if (meta[1] != "blob" or type(meta[0]) is not int or not 1 <= meta[0] <= MAX_ADMISSION_BYTES
            or any(type(value) is not int or value > bound for value, bound in
                   zip(meta[2:], (32, 40, 64, 64, 64, 64, 64)))):
        raise RecoveryRefused("provider_admission_invalid")
    row = conn.execute(
        "SELECT provider,hermes_revision,source_sha256,provider_sha256,lease_id,grant_sha256,"
        "admission_json,admission_sha256 FROM recovery_provider_admissions WHERE session_id=?",
        (session_id,)).fetchone()
    try:
        raw = bytes(row[6])
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate)
        value = ProviderAdmissionValue.model_validate(decoded)
        if (value.canonical_bytes() != raw or hashlib.sha256(raw).hexdigest() != row[7]
                or (value.provider, value.hermes_revision, value.source_sha256,
                    value.provider_sha256, value.reference.lease_id,
                    value.reference.grant_sha256) != tuple(row[:6])
                or value.session_id != session_id):
            raise ValueError("admission mismatch")
        return value
    except (ValueError, TypeError, UnicodeError) as exc:
        raise RecoveryRefused("provider_admission_invalid") from exc


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class ProviderLedger:
    def __init__(self, store: RecoveryStore):
        self.store = store

    def admission(self, scope: RecoveryScope) -> ProviderAdmissionValue:
        self.store._check_scope(scope)
        return self.store._write(lambda conn: read_admission(conn, scope.session_id))

    def _active(self, scope: RecoveryScope, run_id: str, generation: int, producer_id: str) -> object:
        from agent.recovery_context import validate_producer_permit
        from agent.recovery_producers import current_lease, current_registry

        registry, lease = current_registry(), current_lease()
        if (registry is None or lease is None or registry.store is not self.store
                or registry.scope != scope or registry.run_id != run_id
                or registry.generation != generation or lease.registry is not registry
                or lease.producer_id != producer_id or lease._state != "running"
                or not validate_producer_permit(registry.permit, self.store, scope, run_id,
                                                generation)):
            raise RecoveryRefused("invalid_provider_lease")
        return registry

    def begin(self, scope: RecoveryScope, run_id: str, generation: int,
              producer_id: str, kind: Literal["create_environment", "execute"],
              create_invocation_id: str | None = None) -> ProviderInvocationPermit:
        self.store._check_scope(scope)
        self._active(scope, run_id, generation, producer_id)
        if kind not in {"create_environment", "execute"}:
            raise RecoveryRefused("invalid_provider_kind")
        invocation_id = f"provider_{uuid.uuid4().hex}"

        def _tx(conn):
            self.store._owned_member(conn, scope, run_id)
            session = self.store._session(conn, scope)
            if session is None or session[1] != "open":
                raise RecoveryRefused("session_closing")
            read_admission(conn, scope.session_id)
            producer = conn.execute(
                "SELECT state,owner_incarnation FROM recovery_producers WHERE producer_id=? AND run_id=?",
                (producer_id, run_id)).fetchone()
            from agent.recovery_context import current_incarnation
            if producer is None or tuple(producer) != ("running", current_incarnation()):
                raise RecoveryRefused("invalid_provider_lease")
            row = conn.execute(
                "SELECT COUNT(*),COALESCE(MAX(sequence),-1) FROM recovery_provider_invocations "
                "WHERE session_id=?", (scope.session_id,)).fetchone()
            if row[0] >= MAX_INVOCATIONS:
                raise RecoveryRefused("provider_invocation_quota")
            sequence = row[1] + 1
            if kind == "create_environment":
                if create_invocation_id is not None or row[0] != 0:
                    raise RecoveryRefused("provider_create_conflict")
            else:
                create = conn.execute(
                    "SELECT state,container_id,container_attestation_sha256 FROM "
                    "recovery_provider_invocations WHERE invocation_id=? AND session_id=? "
                    "AND kind='create_environment'", (create_invocation_id, scope.session_id)
                ).fetchone()
                if (create is None or create[0] != "returned" or not create[1]
                        or not create[2]):
                    raise RecoveryRefused("provider_create_missing")
            conn.execute(
                "INSERT INTO recovery_provider_invocations"
                "(invocation_id,session_id,run_id,generation,producer_id,sequence,kind,state,"
                "create_invocation_id) VALUES(?,?,?,?,?,?,?,'invoking',?)",
                (invocation_id, scope.session_id, run_id, generation, producer_id,
                 sequence, kind, create_invocation_id),
            )
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

        self.store._write(_tx)
        capability = ProviderInvocationPermit(_ISSUER, invocation_id)
        with _LOCK:
            _CAPABILITIES[capability] = (os.getpid(), _PROCESS_NONCE, id(self.store.db),
                                         self.store.store_id, scope, run_id, generation,
                                         producer_id, kind, create_invocation_id, invocation_id)
        return capability

    def finish(self, capability: ProviderInvocationPermit,
               outcome: ProviderInvocationOutcome) -> None:
        if type(capability) is not ProviderInvocationPermit or type(outcome) is not ProviderInvocationOutcome:
            raise RecoveryRefused("invalid_provider_permit")
        with _LOCK:
            record = _CAPABILITIES.get(capability)
        if record is None or record[:4] != (os.getpid(), _PROCESS_NONCE, id(self.store.db),
                                             self.store.store_id):
            raise RecoveryRefused("invalid_provider_permit")
        _, _, _, _, scope, run_id, generation, producer_id, kind, create_id, invocation_id = record
        if capability.invocation_id != invocation_id:
            raise RecoveryRefused("invalid_provider_permit")
        self._active(scope, run_id, generation, producer_id)
        if outcome.state == "returned":
            if kind == "create_environment":
                if (outcome.container_id is None or outcome.container_attestation_sha256 is None
                        or outcome.exit_code is not None):
                    raise RecoveryRefused("invalid_provider_outcome")
            elif outcome.container_id is not None or outcome.container_attestation_sha256 is not None or outcome.exit_code is None:
                raise RecoveryRefused("invalid_provider_outcome")

        def _tx(conn):
            self.store._owned_member(conn, scope, run_id)
            session = self.store._session(conn, scope)
            if session is None or session[1] == "sealed":
                raise RecoveryRefused("session_closed")
            row = conn.execute(
                "SELECT state,kind,create_invocation_id,container_id,container_attestation_sha256,"
                "exit_code,outcome_reason FROM recovery_provider_invocations WHERE invocation_id=? "
                "AND session_id=? AND run_id=? AND generation=? AND producer_id=?",
                (invocation_id, scope.session_id, run_id, generation,
                 producer_id)).fetchone()
            if row is None or (row[1], row[2]) != (kind, create_id):
                raise RecoveryRefused("invalid_provider_permit")
            expected = (outcome.state, kind, create_id, outcome.container_id,
                        outcome.container_attestation_sha256, outcome.exit_code, outcome.reason)
            if row[0] != "invoking":
                if tuple(row) == expected:
                    return
                raise RecoveryRefused("provider_outcome_conflict")
            if kind == "execute" and outcome.state == "returned":
                create = conn.execute(
                    "SELECT state,container_id,container_attestation_sha256 FROM "
                    "recovery_provider_invocations WHERE invocation_id=? AND session_id=?",
                    (create_id, scope.session_id)).fetchone()
                if create is None or create[0] != "returned" or not create[1] or not create[2]:
                    raise RecoveryRefused("provider_create_missing")
            conn.execute(
                "UPDATE recovery_provider_invocations SET state=?,container_id=?,"
                "container_attestation_sha256=?,exit_code=?,outcome_reason=? "
                "WHERE invocation_id=? AND state='invoking'",
                (outcome.state, outcome.container_id, outcome.container_attestation_sha256,
                 outcome.exit_code, outcome.reason, invocation_id),
            )
            if outcome.state == "unknown":
                self.store._add_reason(conn, scope, "untracked_producer")
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))
            self.store._settle_member(conn, scope, run_id)

        self.store._write(_tx)
        with _LOCK:
            _CAPABILITIES.pop(capability, None)

    def rows(self, scope: RecoveryScope) -> Iterator[ProviderInvocationRow]:
        """Read one bounded indexed row at a time, including independent metadata checks."""
        self.store._check_scope(scope)
        # A single read transaction is necessary for a stable seal snapshot. The
        # sealer can pass its own connection to iter_rows below.
        with self.store.db._read_ctx() as conn:
            conn.execute("BEGIN")
            try:
                yield from iter_rows(conn, scope)
                conn.execute("COMMIT")
            except BaseException:
                conn.rollback()
                raise


def iter_rows(conn: sqlite3.Connection, scope: RecoveryScope) -> Iterator[ProviderInvocationRow]:
    read_admission(conn, scope.session_id)
    count = conn.execute("SELECT COUNT(*) FROM recovery_provider_invocations WHERE session_id=?",
                         (scope.session_id,)).fetchone()[0]
    if type(count) is not int or count > MAX_INVOCATIONS:
        raise RecoveryRefused("provider_invocation_quota")
    create_id: str | None = None
    for expected in range(count):
        meta = conn.execute(
            "SELECT length(invocation_id),length(session_id),length(run_id),length(producer_id),"
            "length(create_invocation_id),length(container_id),"
            "length(container_attestation_sha256),length(outcome_reason) "
            "FROM recovery_provider_invocations "
            "WHERE session_id=? AND sequence=?", (scope.session_id, expected)).fetchone()
        if meta is None or any(value is not None and value > bound for value, bound in
                               zip(meta, (64, 255, 255, 64, 64, 255, 64, 64))):
            raise RecoveryRefused("provider_inventory_invalid")
        row = conn.execute(
            "SELECT invocation_id,session_id,run_id,generation,producer_id,sequence,kind,state,"
            "create_invocation_id,container_id,container_attestation_sha256,exit_code,"
            "outcome_reason FROM recovery_provider_invocations WHERE session_id=? AND sequence=?",
            (scope.session_id, expected)).fetchone()
        try:
            value = ProviderInvocationRow.model_validate(dict(zip(ProviderInvocationRow.model_fields, row)))
        except (ValueError, TypeError) as exc:
            raise RecoveryRefused("provider_inventory_invalid") from exc
        member = conn.execute(
            "SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
            (value.run_id, scope.session_id)).fetchone()
        producer = conn.execute(
            "SELECT run_id FROM recovery_producers WHERE producer_id=?",
            (value.producer_id,)).fetchone()
        if (member is None or member[0] != value.generation or producer is None
                or producer[0] != value.run_id):
            raise RecoveryRefused("provider_inventory_invalid")
        if value.kind == "create_environment":
            if expected != 0 or create_id is not None or value.create_invocation_id is not None:
                raise RecoveryRefused("provider_inventory_invalid")
            create_id = value.invocation_id
        elif create_id is None or value.create_invocation_id != create_id:
            raise RecoveryRefused("provider_inventory_invalid")
        if value.state == "invoking" and any(item is not None for item in (
                value.container_id, value.container_attestation_sha256,
                value.exit_code, value.outcome_reason)):
            raise RecoveryRefused("provider_inventory_invalid")
        if value.state == "unknown" and (value.outcome_reason not in {
                "provider_exception", "lost_result"} or any(item is not None for item in (
                    value.container_id, value.container_attestation_sha256, value.exit_code))):
            raise RecoveryRefused("provider_inventory_invalid")
        if value.state == "returned":
            if value.kind == "create_environment" and (
                    not value.container_id or not value.container_attestation_sha256
                    or value.exit_code is not None or value.outcome_reason is not None):
                raise RecoveryRefused("provider_inventory_invalid")
            if value.kind == "execute" and (
                    value.container_id is not None
                    or value.container_attestation_sha256 is not None
                    or value.exit_code is None or value.outcome_reason is not None):
                raise RecoveryRefused("provider_inventory_invalid")
        yield value
