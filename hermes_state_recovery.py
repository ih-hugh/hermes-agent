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
from typing import TYPE_CHECKING, Literal

from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, RecoveryMember, SealRequest

if TYPE_CHECKING:
    from hermes_state import SessionDB


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
        self._check_scope(identity.scope)
        if not identity.idempotency_key.startswith(RESERVED_KEY_PREFIX):
            return AdmissionResult("refused", None, "reserved_key_required")
        if not identity.owner_incarnation or not identity.run_id or len(identity.request_sha256) != 64:
            return AdmissionResult("refused", None, "invalid_identity")
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
                if conn.execute("SELECT 1 FROM sessions WHERE id=?", (scope.session_id,)).fetchone():
                    return AdmissionResult("refused", None, "existing_session")
                conn.execute(
                    "INSERT INTO recovery_sessions(session_id,profile,scope_digest,phase,revision,root_run_id) "
                    "VALUES(?,?,?,'open',1,?)",
                    (scope.session_id, scope.profile, scope.scope_digest, identity.run_id))
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

        result = self.db._execute_write(_tx)
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
        self.db._write_rowcount("UPDATE recovery_members SET status_json=? WHERE run_id=?", (encoded, run_id))

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

        return self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

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
            self.db._execute_write(_tx)
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

        self.db._execute_write(_tx)

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

        self.db._execute_write(_tx)

    def send_inventory(self, scope: RecoveryScope, run_id: str) -> tuple[tuple[str, int, str, str], ...]:
        self._check_scope(scope)
        def _read(conn):
            return tuple(tuple(row) for row in conn.execute(
                "SELECT a.attempt_id,a.sequence,a.state,a.delta_id FROM recovery_sends a "
                "JOIN recovery_members m ON m.run_id=a.run_id WHERE a.run_id=? AND m.session_id=? "
                "AND m.profile=? AND m.scope_digest=? ORDER BY a.sequence",
                (run_id, scope.session_id, scope.profile, scope.scope_digest)).fetchall())
        return self.db._read_retrying_ioerr(_read)
