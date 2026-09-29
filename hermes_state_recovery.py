"""Durable admission authority for explicitly protected API sessions.

Every transition uses SessionDB's one BEGIN IMMEDIATE writer. Ordinary transport
retention and process memory cannot grant or erase protected membership.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Literal

from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, RecoveryMember, SealRequest

if TYPE_CHECKING:
    from hermes_state import SessionDB
    from hermes_state_usage import RetainedUsagePayload
    from hermes_state_recovery_provider import ProviderAdmissionValue


RESERVED_KEY_PREFIX = "byf-recovery-v1:"
INCOMPLETE_REASONS = frozenset({
    "lost_producer_owner", "missing_membership", "unknown_send_outcome",
    "failed_usage_acknowledgement", "untracked_producer", "unsupported_configuration",
    "unclosed_producer", "untracked_write",
})


class RecoveryRefused(ValueError):
    """Stable refusal code; arbitrary database or exception text is never returned."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveryScope:
    store_id: str
    profile: str
    scope_digest: str
    session_id: str


@dataclass(frozen=True, slots=True)
class AdmissionIdentity:
    scope: RecoveryScope
    idempotency_key: str
    request_sha256: str
    run_id: str
    owner_incarnation: str
    provider_admission: ProviderAdmissionValue
    initial_status: dict | None = None


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    outcome: Literal["created", "replayed", "conflict", "refused"]
    member: RecoveryMember | None
    reason: str | None = None
    handoff: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class CloseView:
    phase: Literal["open", "closing", "sealed"]
    revision: int
    members: tuple[RecoveryMember, ...]
    request_id: str | None
    state: Literal["pending", "unsupported", "sealed"]
    reason_codes: tuple[str, ...]
    receipt_ref: str | None = None


def membership_sha256(run_ids: list[str] | tuple[str, ...]) -> str:
    return hashlib.sha256(json.dumps(list(run_ids), separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class RecoveryStore:
    def __init__(self, db: SessionDB):
        self.db = db
        path = Path(db.db_path)
        if db.read_only or path.name == ":memory:" or not path.is_file():
            raise RecoveryRefused("durable_store_required")
        row = db._read_one("SELECT store_id FROM recovery_store WHERE singleton=1")
        if row is None:
            raise RecoveryRefused("durable_store_required")
        self.store_id = str(row[0])

    def _write(self, fn, *, patience_s: float | None = None):
        """Run an authoritative ledger transition on its exact writer connection."""
        from agent.recovery_context import _store_writer

        def _authorized(conn):
            with _store_writer(self.db, conn):
                return fn(conn)

        return self.db._execute_write(_authorized, patience_s=patience_s)

    def _check_scope(self, scope: RecoveryScope) -> None:
        if (scope.store_id != self.store_id or not scope.profile or not scope.scope_digest
                or not scope.session_id):
            raise RecoveryRefused("scope_mismatch")

    @staticmethod
    def _member(row) -> RecoveryMember:
        return RecoveryMember(run_id=row[0], generation=row[1], parent_run_id=row[2],
                              request_sha256=row[3], producer_state=row[4])

    @classmethod
    def _view(cls, conn, session_row) -> CloseView:
        session_id, phase, revision, request_id, reasons, receipt = session_row
        rows = conn.execute(
            "SELECT run_id,generation,parent_run_id,request_sha256,producer_state "
            "FROM recovery_members WHERE session_id=? ORDER BY generation", (session_id,)).fetchall()
        members = tuple(cls._member(row) for row in rows)
        codes = tuple(json.loads(reasons))
        state = "sealed" if phase == "sealed" else "unsupported" if codes else "pending"
        return CloseView(phase, revision, members, request_id, state, codes,
                         hashlib.sha256(receipt.encode()).hexdigest() if receipt else None)

    @staticmethod
    def _session(conn, scope: RecoveryScope):
        return conn.execute(
            "SELECT session_id,phase,revision,close_request_id,reason_codes_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=? AND profile=? AND scope_digest=?",
            (scope.session_id, scope.profile, scope.scope_digest)).fetchone()

    def reserve(self, admission: RecoveryAdmission, identity: AdmissionIdentity) -> AdmissionResult:
        from hermes_state_recovery_provider import ProviderAdmissionValue, insert_admission, read_admission

        self._check_scope(identity.scope)
        if not identity.idempotency_key.startswith(RESERVED_KEY_PREFIX):
            return AdmissionResult("refused", None, "reserved_key_required")
        if not identity.owner_incarnation or not identity.run_id or len(identity.request_sha256) != 64:
            return AdmissionResult("refused", None, "invalid_identity")
        if (type(identity.provider_admission) is not ProviderAdmissionValue
                or identity.provider_admission.session_id != identity.scope.session_id):
            return AdmissionResult("refused", None, "provider_admission_invalid")
        try:
            admission_bytes = identity.provider_admission.canonical_bytes()
        except RecoveryRefused as exc:
            return AdmissionResult("refused", None, exc.code)
        scope = identity.scope

        def _tx(conn):
            # Global within the authenticated profile/scope, independent of session ID.
            existing = conn.execute(
                "SELECT run_id,generation,parent_run_id,request_sha256,producer_state,session_id "
                "FROM recovery_members WHERE profile=? AND scope_digest=? AND idempotency_key=?",
                (scope.profile, scope.scope_digest, identity.idempotency_key)).fetchone()
            if existing is not None:
                member = self._member(existing)
                matching = (existing[5] == scope.session_id and existing[1] == admission.generation
                            and existing[2] == admission.parent_run_id and
                            hmac.compare_digest(existing[3], identity.request_sha256))
                return AdmissionResult("replayed" if matching else "conflict", member)
            # The old transport store is a different DB. Protected keys are never written
            # there, and a collision found by the API adapter is refused before this call.
            row = self._session(conn, scope)
            if admission.generation == 0:
                if admission.parent_run_id is not None or row is not None:
                    return AdmissionResult("refused", None, "root_conflict")
                from hermes_state_recovery_exclusions import root_exclusion

                exclusion = root_exclusion(conn, scope.session_id)
                if exclusion is not None:
                    return AdmissionResult("refused", None, exclusion)
                if conn.execute("SELECT 1 FROM sessions WHERE id=?", (scope.session_id,)).fetchone():
                    return AdmissionResult("refused", None, "existing_session")
                from hermes_state_recovery_guard import install_recovery_guards
                install_recovery_guards(conn)
                conn.execute(
                    "INSERT INTO recovery_sessions(session_id,profile,scope_digest,phase,revision,root_run_id) "
                    "VALUES(?,?,?,'open',1,?)",
                    (scope.session_id, scope.profile, scope.scope_digest, identity.run_id))
                insert_admission(conn, identity.provider_admission)
            else:
                if row is None or row[1] != "open":
                    return AdmissionResult("refused", None, "not_open")
                root = conn.execute(
                    "SELECT run_id,producer_state FROM recovery_members WHERE session_id=? AND generation=0",
                    (scope.session_id,)).fetchone()
                if (root is None or admission.parent_run_id != root[0] or root[1] != "closed" or
                        conn.execute("SELECT 1 FROM recovery_members WHERE session_id=? AND generation=1",
                                     (scope.session_id,)).fetchone()):
                    return AdmissionResult("refused", None, "nudge_unavailable")
                if read_admission(conn, scope.session_id).canonical_bytes() != admission_bytes:
                    return AdmissionResult("refused", None, "provider_admission_mismatch")
                conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                             (scope.session_id,))
            conn.execute(
                "INSERT INTO recovery_members(run_id,session_id,generation,parent_run_id,profile,scope_digest,"
                "idempotency_key,request_sha256,owner_incarnation,producer_state,status_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,'open',?)",
                (identity.run_id, scope.session_id, admission.generation, admission.parent_run_id,
                 scope.profile, scope.scope_digest, identity.idempotency_key, identity.request_sha256,
                 identity.owner_incarnation, json.dumps(identity.initial_status or {"status": "queued"},
                                                        sort_keys=True, separators=(",", ":"))))
            return AdmissionResult("created", RecoveryMember(
                run_id=identity.run_id, generation=admission.generation,
                parent_run_id=admission.parent_run_id, request_sha256=identity.request_sha256,
                producer_state="open"))

        result = self._write(_tx)
        if result.outcome == "created":
            from agent.recovery_context import _register_admission_handoff
            return replace(result, handoff=_register_admission_handoff(
                self, identity, admission.generation))
        return result

    def lookup_key(self, scope: RecoveryScope, key: str, fingerprint: str) -> AdmissionResult | None:
        self._check_scope(scope)
        row = self.db._read_one(
            "SELECT run_id,generation,parent_run_id,request_sha256,producer_state,session_id "
            "FROM recovery_members WHERE profile=? AND scope_digest=? AND idempotency_key=?",
            (scope.profile, scope.scope_digest, key))
        if row is None:
            return None
        member = self._member(row)
        same = row[5] == scope.session_id and hmac.compare_digest(row[3], fingerprint)
        return AdmissionResult("replayed" if same else "conflict", member)

    def owns_run(self, profile: str, scope_digest: str, run_id: str) -> bool:
        return self.db._read_one(
            "SELECT 1 FROM recovery_members WHERE profile=? AND scope_digest=? AND run_id=?",
            (profile, scope_digest, run_id)) is not None

    def status_for_run(self, profile: str, scope_digest: str, run_id: str) -> dict | None:
        row = self.db._read_one(
            "SELECT status_json FROM recovery_members WHERE profile=? AND scope_digest=? AND run_id=?",
            (profile, scope_digest, run_id))
        return json.loads(row[0]) if row is not None else None

    def update_status(self, run_id: str, status: dict) -> None:
        encoded = json.dumps(status, sort_keys=True, separators=(",", ":"))
        self._write(lambda conn: conn.execute(
            "UPDATE recovery_members SET status_json=? WHERE run_id=?", (encoded, run_id)))

    def reserve_usage_payload(self, permit: object, delta: object, digest: str) -> str:
        """Pin the first accepted payload before the worker crosses a thread boundary."""
        from agent.recovery_context import current_incarnation, usage_write_binding
        from hermes_state_usage import UsageDelta

        binding = usage_write_binding(permit, self)
        if (binding is None or type(delta) is not UsageDelta
                or delta.write_id != binding.delta_id
                or delta.attempt_id != binding.attempt_id or delta.generation != binding.generation):
            raise RecoveryRefused("invalid_usage_permit")
        payload = delta.canonical_bytes()
        if delta.digest() != digest:
            raise RecoveryRefused("usage_payload_conflict")

        def _tx(conn):
            row = conn.execute(
                "SELECT s.state,s.payload_sha256,s.payload_json,a.state,p.state,p.owner_incarnation,"
                "m.producer_state,m.owner_incarnation,s.ack_revision,a.delta_id,p.run_id "
                "FROM recovery_usage_slots s "
                "JOIN recovery_sends a USING(attempt_id) "
                "JOIN recovery_producers p ON p.producer_id=a.producer_id "
                "JOIN recovery_members m ON m.run_id=a.run_id "
                "WHERE s.delta_id=? AND s.attempt_id=? AND a.run_id=? AND a.producer_id=? "
                "AND m.session_id=? AND m.generation=? AND m.profile=? AND m.scope_digest=?",
                (binding.delta_id, binding.attempt_id, binding.run_id, binding.producer_id,
                 binding.scope.session_id, binding.generation, binding.scope.profile,
                 binding.scope.scope_digest),
            ).fetchone()
            if (row is None or row[9] != binding.delta_id
                    or row[10] != binding.run_id):
                raise RecoveryRefused("invalid_usage_permit")
            if (row[1] is None) != (row[2] is None):
                raise RecoveryRefused("invalid_retained_usage_payload")
            if row[1] is not None and (row[1] != digest or row[2] != payload):
                raise RecoveryRefused("usage_payload_conflict")
            if (row[0] == "committed" and
                    (row[2] is None or type(row[8]) is not int or row[8] <= 0)):
                raise RecoveryRefused("invalid_retained_usage_payload")
            if row[0] == "committed":
                return "committed"
            if row[0] != "pending":
                raise RecoveryRefused("usage_write_failed")
            if (row[3] != "invoking" or row[4] not in {"running", "closed"}
                    or row[5:8] != (current_incarnation(), "open", current_incarnation())):
                raise RecoveryRefused("invalid_usage_permit")
            if row[1] is None:
                conn.execute(
                    "UPDATE recovery_usage_slots SET payload_sha256=?,payload_json=? "
                    "WHERE delta_id=? AND payload_sha256 IS NULL AND payload_json IS NULL",
                    (digest, payload, binding.delta_id),
                )
            return "pending"

        return self._write(_tx)

    def apply_usage_delta(self, permit: object, delta: object, digest: str) -> None:
        """Apply session/model counters and acknowledgement in one guarded transaction."""
        from agent.recovery_context import _usage_apply, usage_write_binding
        from hermes_state_usage import (
            UsageDelta, _TOKEN_UPDATE_DELTA_SQL, _validate_protected_usage_totals,
        )

        binding = usage_write_binding(permit, self)
        if (binding is None or type(delta) is not UsageDelta
                or binding.delta_id != delta.write_id
                or binding.attempt_id != delta.attempt_id or binding.generation != delta.generation):
            raise RecoveryRefused("invalid_usage_permit")
        submitted = delta.canonical_bytes()
        if delta.digest() != digest:
            raise RecoveryRefused("usage_payload_conflict")

        def _tx(conn):
            slot = conn.execute(
                "SELECT s.state,s.payload_sha256,s.payload_json,s.ack_revision,"
                "a.run_id,a.producer_id,m.generation,p.run_id,a.delta_id "
                "FROM recovery_usage_slots s JOIN recovery_sends a USING(attempt_id) "
                "JOIN recovery_members m ON m.run_id=a.run_id "
                "JOIN recovery_producers p ON p.producer_id=a.producer_id "
                "WHERE s.delta_id=? AND s.attempt_id=? AND m.session_id=? "
                "AND m.profile=? AND m.scope_digest=?",
                (binding.delta_id, binding.attempt_id, binding.scope.session_id,
                 binding.scope.profile, binding.scope.scope_digest),
            ).fetchone()
            if (slot is None or (slot[4], slot[5], slot[6], slot[7], slot[8]) !=
                    (binding.run_id, binding.producer_id, binding.generation,
                     binding.run_id, binding.delta_id)):
                raise RecoveryRefused("invalid_usage_permit")
            retained = UsageDelta.from_canonical_bytes(slot[2], slot[1])
            if (slot[1] != digest or slot[2] != submitted
                    or retained.write_id != binding.delta_id
                    or retained.attempt_id != binding.attempt_id
                    or retained.generation != binding.generation):
                raise RecoveryRefused("usage_payload_conflict")
            if slot[0] == "committed":
                if type(slot[3]) is not int or slot[3] <= 0:
                    raise RecoveryRefused("invalid_retained_usage_payload")
                return
            if slot[0] != "pending":
                raise RecoveryRefused("usage_write_failed")
            row = conn.execute(
                "SELECT id,model,billing_provider,api_call_count FROM sessions WHERE id=?",
                (binding.scope.session_id,),
            ).fetchone()
            if row is None:
                raise RecoveryRefused("protected_session_missing")
            # Row triggers re-check live member, send, producer and slot on this same
            # connection. The private usage context narrows this permit to these counters.
            with _usage_apply(self.db, conn, permit):
                if (int(row[3] or 0) == 0 and retained.model and retained.billing_provider
                        and (row[1] != retained.model or row[2] != retained.billing_provider)):
                    conn.execute(
                        "UPDATE sessions SET model=?,billing_provider=?,billing_base_url=?,"
                        "billing_mode=? WHERE id=?",
                        (retained.model, retained.billing_provider, retained.billing_base_url,
                         retained.billing_mode, binding.scope.session_id),
                    )
                conn.execute(_TOKEN_UPDATE_DELTA_SQL, (
                    retained.input_tokens, retained.output_tokens, retained.cache_read_tokens,
                    retained.cache_write_tokens, retained.reasoning_tokens,
                    retained.estimated_cost_usd, retained.actual_cost_usd, retained.actual_cost_usd,
                    retained.cost_status, retained.cost_source, retained.pricing_version,
                    retained.billing_provider, retained.billing_base_url, retained.billing_mode,
                    retained.model, retained.api_call_count, binding.scope.session_id,
                ))
                self.db._record_model_usage(
                    conn, binding.scope.session_id, model=retained.model,
                    billing_provider=retained.billing_provider,
                    billing_base_url=retained.billing_base_url,
                    billing_mode=retained.billing_mode,
                    input_tokens=retained.input_tokens, output_tokens=retained.output_tokens,
                    cache_read_tokens=retained.cache_read_tokens,
                    cache_write_tokens=retained.cache_write_tokens,
                    reasoning_tokens=retained.reasoning_tokens,
                    estimated_cost_usd=retained.estimated_cost_usd,
                    actual_cost_usd=retained.actual_cost_usd,
                    cost_status=retained.cost_status, cost_source=retained.cost_source,
                    api_call_count=retained.api_call_count,
                )
                _validate_protected_usage_totals(conn, binding.scope.session_id, retained)
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (binding.scope.session_id,))
            revision = conn.execute("SELECT revision FROM recovery_sessions WHERE session_id=?",
                                    (binding.scope.session_id,)).fetchone()[0]
            conn.execute(
                "UPDATE recovery_usage_slots SET state='committed',ack_revision=? "
                "WHERE delta_id=? AND state='pending'", (revision, binding.delta_id),
            )

        self._write(_tx)

    def iter_committed_usage_payloads(
        self, scope: RecoveryScope, *, conn: sqlite3.Connection,
    ) -> Iterator[RetainedUsagePayload]:
        """Yield one checked delta at a time inside the caller's finalization transaction."""
        from hermes_state_usage import RetainedUsagePayload, UsageDelta, _MAX_USAGE_PAYLOAD_BYTES

        self._check_scope(scope)
        sql = (
            "SELECT s.delta_id,s.attempt_id,s.payload_sha256,length(s.payload_json),"
            "typeof(s.payload_json),s.ack_revision,a.run_id,a.producer_id,m.generation,"
            "p.run_id,a.delta_id "
            "FROM recovery_usage_slots s JOIN recovery_sends a USING(attempt_id) "
            "JOIN recovery_members m ON m.run_id=a.run_id "
            "JOIN recovery_producers p ON p.producer_id=a.producer_id "
            "WHERE m.session_id=? AND m.profile=? AND m.scope_digest=? AND s.state='committed' "
            "ORDER BY s.ack_revision,s.delta_id"
        )
        params = (scope.session_id, scope.profile, scope.scope_digest)
        cursor = conn.execute(sql, params)
        try:
            for row in cursor:
                # The ordered cursor holds only small metadata. Never fetch an
                # unbounded corrupt BLOB into Python or SQLite's sort buffer.
                if (row[0] != row[10] or row[6] != row[9]
                        or row[4] != "blob" or type(row[3]) is not int
                        or not 0 < row[3] <= _MAX_USAGE_PAYLOAD_BYTES):
                    raise RecoveryRefused("invalid_retained_usage_payload")
                payload_row = conn.execute(
                    "SELECT payload_json FROM recovery_usage_slots WHERE delta_id=? "
                    "AND typeof(payload_json)='blob' AND length(payload_json)=?",
                    (row[0], row[3]),
                ).fetchone()
                if payload_row is None:
                    raise RecoveryRefused("invalid_retained_usage_payload")
                payload = payload_row[0]
                delta = UsageDelta.from_canonical_bytes(payload, row[2])
                if (delta.write_id != row[0] or delta.attempt_id != row[1]
                        or delta.generation != row[8]
                        or type(row[5]) is not int or row[5] <= 0):
                    raise RecoveryRefused("invalid_retained_usage_payload")
                yield RetainedUsagePayload(
                    run_id=row[6], producer_id=row[7], ack_revision=row[5],
                    payload_sha256=row[2], payload_json=payload, delta=delta,
                )
        finally:
            cursor.close()

    def fail_usage_delta(self, permit: object) -> None:
        """Retain a sticky failure; an unavailable DB leaves the slot pending instead."""
        from agent.recovery_context import usage_write_binding

        binding = usage_write_binding(permit, self)
        if binding is None:
            raise RecoveryRefused("invalid_usage_permit")

        def _tx(conn):
            changed = conn.execute(
                "UPDATE recovery_usage_slots SET state='abandoned' "
                "WHERE delta_id=? AND attempt_id=? AND state='pending'",
                (binding.delta_id, binding.attempt_id),
            ).rowcount
            if changed:
                self._add_reason(conn, binding.scope, "failed_usage_acknowledgement")
                self._settle_member(conn, binding.scope, binding.run_id)

        self._write(_tx)

    def begin_close(self, scope: RecoveryScope, request: SealRequest) -> CloseView:
        self._check_scope(scope)
        if request.session_id != scope.session_id:
            raise RecoveryRefused("scope_mismatch")

        def _tx(conn):
            row = self._session(conn, scope)
            if row is None:
                raise RecoveryRefused("not_found")
            view = self._view(conn, row)
            recorded = conn.execute(
                "SELECT close_request_json FROM recovery_sessions WHERE session_id=?", (scope.session_id,)
            ).fetchone()[0]
            exact = request.model_dump_json()
            if recorded is not None:
                if recorded != exact:
                    raise RecoveryRefused("close_conflict")
                return view
            ordered = [m.run_id for m in view.members]
            reasons = list(view.reason_codes)
            if tuple(ordered) != request.run_ids or membership_sha256(ordered) != request.expected_membership_sha256:
                if "missing_membership" not in reasons:
                    reasons.append("missing_membership")
            conn.execute(
                "UPDATE recovery_sessions SET phase='closing',revision=revision+1,"
                "close_request_id=?,close_request_json=?,reason_codes_json=? WHERE session_id=?",
                (request.request_id, exact, json.dumps(reasons), scope.session_id))
            return self._view(conn, self._session(conn, scope))

        return self._write(_tx)

    def lookup(self, scope: RecoveryScope, request_id: str) -> CloseView:
        self._check_scope(scope)
        return self._read_close_snapshot(
            "SELECT session_id,phase,revision,close_request_id,reason_codes_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=? AND profile=? AND scope_digest=? AND close_request_id=?",
            (scope.session_id, scope.profile, scope.scope_digest, request_id))

    def lookup_root(self, scope: RecoveryScope, root_id: str) -> CloseView:
        self._check_scope(scope)
        return self._read_close_snapshot(
            "SELECT session_id,phase,revision,close_request_id,reason_codes_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=? AND profile=? AND scope_digest=? "
            "AND root_run_id=? AND close_request_id IS NOT NULL",
            (scope.session_id, scope.profile, scope.scope_digest, root_id))

    def _read_close_snapshot(self, query: str, params: tuple[str, ...]) -> CloseView:
        """Session revision and ordered members come from one SQLite read snapshot."""
        def _read(conn):
            conn.execute("BEGIN")
            try:
                row = conn.execute(query, params).fetchone()
                if row is None:
                    raise RecoveryRefused("not_found")
                view = self._view(conn, row)
                conn.execute("COMMIT")
                return view
            except BaseException:
                conn.rollback()
                raise

        return self.db._read_retrying_ioerr(_read)

    def close_producer(self, scope: RecoveryScope, run_id: str, permit: object) -> None:
        """Complete the root only after all inventoried work has drained."""
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one(
            "SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
            (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            conn.execute("INSERT OR IGNORE INTO recovery_root_done(run_id) VALUES(?)", (run_id,))
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def mark_incomplete(self, scope: RecoveryScope, run_id: str, permit: object, reason: str) -> None:
        """Record a sticky reason and close only after inventoried work drains."""
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        if reason not in INCOMPLETE_REASONS:
            raise RecoveryRefused("invalid_reason")
        row = self.db._read_one(
            "SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
            (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            session = self._session(conn, scope)
            if session is None or session[1] == "sealed":
                raise RecoveryRefused("session_closed")
            self._add_reason(conn, scope, reason)
            conn.execute("INSERT OR IGNORE INTO recovery_root_done(run_id) VALUES(?)", (run_id,))
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def _owned_member(self, conn, scope: RecoveryScope, run_id: str) -> None:
        from agent.recovery_context import current_incarnation

        row = conn.execute(
            "SELECT owner_incarnation,producer_state FROM recovery_members "
            "WHERE run_id=? AND session_id=? AND profile=? AND scope_digest=?",
            (run_id, scope.session_id, scope.profile, scope.scope_digest)).fetchone()
        if row is None or row[0] != current_incarnation() or row[1] != "open":
            raise RecoveryRefused("foreign_producer")

    @staticmethod
    def _add_reason(conn, scope: RecoveryScope, reason: str) -> None:
        if reason not in INCOMPLETE_REASONS:
            raise RecoveryRefused("invalid_reason")
        row = conn.execute(
            "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
            (scope.session_id,)).fetchone()
        if row is None:
            raise RecoveryRefused("not_found")
        reasons = list(json.loads(row[0]))
        if reason not in reasons:
            reasons.append(reason)
            conn.execute("UPDATE recovery_sessions SET reason_codes_json=?,revision=revision+1 WHERE session_id=?",
                         (json.dumps(reasons), scope.session_id))

    @staticmethod
    def _settle_member(conn, scope: RecoveryScope, run_id: str) -> None:
        if conn.execute("SELECT 1 FROM recovery_root_done WHERE run_id=?", (run_id,)).fetchone() is None:
            return
        if conn.execute("SELECT 1 FROM recovery_producers WHERE run_id=? AND state IN ('queued','running') LIMIT 1",
                        (run_id,)).fetchone() is not None:
            return
        if conn.execute("SELECT 1 FROM recovery_sends WHERE run_id=? AND state IN ('reserved','invoking') LIMIT 1",
                        (run_id,)).fetchone() is not None:
            return
        if conn.execute("SELECT 1 FROM recovery_usage_slots s JOIN recovery_sends a USING(attempt_id) "
                        "WHERE a.run_id=? AND s.state='pending' LIMIT 1", (run_id,)).fetchone() is not None:
            return
        if conn.execute("SELECT 1 FROM recovery_write_acks WHERE run_id=? AND state='pending' LIMIT 1",
                        (run_id,)).fetchone() is not None:
            return
        if conn.execute("SELECT 1 FROM recovery_provider_invocations WHERE run_id=? "
                        "AND state='invoking' LIMIT 1", (run_id,)).fetchone() is not None:
            return
        reasons = conn.execute("SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
                               (scope.session_id,)).fetchone()
        state = "incomplete" if reasons and json.loads(reasons[0]) else "closed"
        changed = conn.execute("UPDATE recovery_members SET producer_state=? "
                               "WHERE run_id=? AND session_id=? AND producer_state='open'",
                               (state, run_id, scope.session_id)).rowcount
        if changed:
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

    def register_producer(self, scope: RecoveryScope, run_id: str, permit: object,
                          producer_id: str, kind: str, parent_producer_id: str | None = None) -> None:
        from agent.recovery_context import current_incarnation, validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")
        if kind not in {"executor", "tool", "sdk", "callback", "usage_write"}:
            raise RecoveryRefused("invalid_producer_kind")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            session = self._session(conn, scope)
            if session is None or session[1] == "sealed":
                raise RecoveryRefused("session_closing")
            root_done = conn.execute("SELECT 1 FROM recovery_root_done WHERE run_id=?",
                                     (run_id,)).fetchone() is not None
            if parent_producer_id is None:
                if session[1] != "open" or root_done:
                    raise RecoveryRefused("session_closing")
            else:
                if kind != "callback":
                    raise RecoveryRefused("invalid_callback_parent")
                parent = conn.execute(
                    "SELECT kind,state,owner_incarnation FROM recovery_producers "
                    "WHERE producer_id=? AND run_id=?",
                    (parent_producer_id, run_id)).fetchone()
                if (parent is None or parent[1] != "running" or
                        parent[2] != current_incarnation() or parent[0] == "usage_write"):
                    raise RecoveryRefused("invalid_callback_parent")
            conn.execute("INSERT INTO recovery_producers"
                         "(producer_id,run_id,kind,state,owner_incarnation,parent_producer_id) "
                         "VALUES(?,?,?,'queued',?,?)",
                         (producer_id, run_id, kind, current_incarnation(), parent_producer_id))
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

        self._write(_tx)

    def start_registered_producer(self, scope: RecoveryScope, run_id: str, permit: object,
                                  producer_id: str) -> None:
        self._transition_producer(scope, run_id, permit, producer_id, "running", "queued")

    def close_registered_producer(self, scope: RecoveryScope, run_id: str, permit: object,
                                  producer_id: str) -> None:
        self._transition_producer(scope, run_id, permit, producer_id, "closed", "running")

    def cancel_registered_producer(self, scope: RecoveryScope, run_id: str, permit: object,
                                   producer_id: str) -> None:
        self._transition_producer(scope, run_id, permit, producer_id, "cancelled", "queued")

    def _transition_producer(self, scope: RecoveryScope, run_id: str, permit: object,
                             producer_id: str, destination: str, source: str) -> None:
        from agent.recovery_context import current_incarnation, validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            changed = conn.execute("UPDATE recovery_producers SET state=? WHERE producer_id=? AND run_id=? "
                                   "AND owner_incarnation=? AND state=?",
                                   (destination, producer_id, run_id, current_incarnation(), source)).rowcount
            if changed != 1:
                raise RecoveryRefused("producer_transition_refused")
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def request_producer_close(self, scope: RecoveryScope, run_id: str, permit: object) -> None:
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            conn.execute("INSERT OR IGNORE INTO recovery_root_done(run_id) VALUES(?)", (run_id,))
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def note_producer_incomplete(self, scope: RecoveryScope, run_id: str, permit: object,
                                 reason: str) -> None:
        """Record a sticky refusal while retaining authority to drain registered workers."""
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            self._add_reason(conn, scope, reason)
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def begin_send(self, scope: RecoveryScope, run_id: str, permit: object, producer_id: str,
                   attempt_id: str, delta_id: str) -> None:
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            session = self._session(conn, scope)
            if session is None or session[1] != "open":
                raise RecoveryRefused("session_closing")
            if conn.execute("SELECT 1 FROM recovery_root_done WHERE run_id=?",
                            (run_id,)).fetchone() is not None:
                raise RecoveryRefused("session_closing")
            owner = conn.execute("SELECT kind,state FROM recovery_producers WHERE producer_id=? AND run_id=?",
                                 (producer_id, run_id)).fetchone()
            if owner is None or owner[0] != "sdk" or owner[1] != "running":
                raise RecoveryRefused("invalid_send_producer")
            ordinal = conn.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM recovery_sends WHERE run_id=?",
                                   (run_id,)).fetchone()[0]
            conn.execute("INSERT INTO recovery_sends(attempt_id,run_id,producer_id,sequence,state,delta_id) "
                         "VALUES(?,?,?,?,'reserved',?)",
                         (attempt_id, run_id, producer_id, ordinal, delta_id))
            conn.execute("INSERT INTO recovery_usage_slots(delta_id,attempt_id,state) VALUES(?,?,'pending')",
                         (delta_id, attempt_id))
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

        try:
            self._write(_tx)
        except sqlite3.IntegrityError as exc:
            raise RecoveryRefused("send_attempt_reused") from exc

    def invoke_send(self, scope: RecoveryScope, run_id: str, permit: object, attempt_id: str) -> None:
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            changed = conn.execute("UPDATE recovery_sends SET state='invoking' WHERE attempt_id=? AND run_id=? "
                                   "AND state='reserved'", (attempt_id, run_id)).rowcount
            if changed != 1:
                raise RecoveryRefused("send_attempt_consumed")
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

        self._write(_tx)

    def finish_send(self, scope: RecoveryScope, run_id: str, permit: object, attempt_id: str,
                    outcome: str, reason: str | None = None) -> None:
        from agent.recovery_context import validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one("SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
                                (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            self._owned_member(conn, scope, run_id)
            send = conn.execute("SELECT state,delta_id FROM recovery_sends WHERE attempt_id=? AND run_id=?",
                                (attempt_id, run_id)).fetchone()
            if send is None or send[0] not in {"reserved", "invoking"}:
                raise RecoveryRefused("send_attempt_consumed")
            if outcome == "accounted":
                slot = conn.execute("SELECT state FROM recovery_usage_slots WHERE delta_id=? AND attempt_id=?",
                                    (send[1], attempt_id)).fetchone()
                if send[0] != "invoking" or slot is None or slot[0] != "committed":
                    raise RecoveryRefused("usage_ack_required")
            elif outcome == "no_charge_proved":
                if send[0] != "reserved" or reason != "sdk_not_entered":
                    raise RecoveryRefused("no_charge_proof_required")
                conn.execute("UPDATE recovery_usage_slots SET state='no_charge' WHERE delta_id=?", (send[1],))
            elif outcome == "unknown":
                conn.execute("UPDATE recovery_usage_slots SET state='abandoned' WHERE delta_id=? AND state='pending'",
                             (send[1],))
                self._add_reason(conn, scope, "unknown_send_outcome")
            else:
                raise RecoveryRefused("invalid_send_outcome")
            conn.execute("UPDATE recovery_sends SET state=?,reason=? WHERE attempt_id=?",
                         (outcome, reason, attempt_id))
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))
            self._settle_member(conn, scope, run_id)

        self._write(_tx)

    def send_inventory(self, scope: RecoveryScope, run_id: str) -> tuple[tuple[str, int, str, str], ...]:
        self._check_scope(scope)
        def _read(conn):
            return tuple(tuple(row) for row in conn.execute(
                "SELECT a.attempt_id,a.sequence,a.state,a.delta_id FROM recovery_sends a "
                "JOIN recovery_members m ON m.run_id=a.run_id WHERE a.run_id=? AND m.session_id=? "
                "AND m.profile=? AND m.scope_digest=? ORDER BY a.sequence",
                (run_id, scope.session_id, scope.profile, scope.scope_digest)).fetchall())
        return self.db._read_retrying_ioerr(_read)
