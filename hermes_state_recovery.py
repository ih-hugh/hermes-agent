"""Durable admission authority for explicitly protected API sessions.

Every transition uses SessionDB's one BEGIN IMMEDIATE writer. Ordinary transport
retention and process memory cannot grant or erase protected membership.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
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

        return self.db._execute_write(_tx)

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
            if ordered != request.run_ids or membership_sha256(ordered) != request.expected_membership_sha256:
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
        row = self.db._read_one(
            "SELECT session_id,phase,revision,close_request_id,reason_codes_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=? AND profile=? AND scope_digest=? AND close_request_id=?",
            (scope.session_id, scope.profile, scope.scope_digest, request_id))
        if row is None:
            raise RecoveryRefused("not_found")
        return self.db._read_retrying_ioerr(lambda conn: self._view(conn, row))

    def lookup_root(self, scope: RecoveryScope, root_id: str) -> CloseView:
        self._check_scope(scope)
        row = self.db._read_one(
            "SELECT session_id,phase,revision,close_request_id,reason_codes_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=? AND profile=? AND scope_digest=? AND root_run_id=?",
            (scope.session_id, scope.profile, scope.scope_digest, root_id))
        if row is None:
            raise RecoveryRefused("not_found")
        return self.db._read_retrying_ioerr(lambda conn: self._view(conn, row))

    def close_producer(self, scope: RecoveryScope, run_id: str, permit: object) -> None:
        """Only the live process that owns an issued permit may close its producer."""
        from agent.recovery_context import current_incarnation, validate_producer_permit

        self._check_scope(scope)
        row = self.db._read_one(
            "SELECT generation FROM recovery_members WHERE run_id=? AND session_id=?",
            (run_id, scope.session_id))
        if row is None or not validate_producer_permit(permit, self, scope, run_id, int(row[0])):
            raise RecoveryRefused("invalid_producer_permit")

        def _tx(conn):
            changed = conn.execute(
                "UPDATE recovery_members SET producer_state='closed' WHERE run_id=? AND session_id=? "
                "AND producer_state='open' AND owner_incarnation=?",
                (run_id, scope.session_id, current_incarnation())).rowcount
            if changed != 1:
                raise RecoveryRefused("invalid_producer_permit")
            conn.execute("UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                         (scope.session_id,))

        self.db._execute_write(_tx)

    def mark_incomplete(self, scope: RecoveryScope, run_id: str, permit: object, reason: str) -> None:
        """Record a sticky, bounded reason from the member's actual owner."""
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
            session = self._session(conn, scope)
            if session is None or session[1] == "sealed":
                raise RecoveryRefused("session_closed")
            codes = list(json.loads(session[4]))
            if reason not in codes:
                codes.append(reason)
            conn.execute(
                "UPDATE recovery_members SET producer_state='incomplete' WHERE run_id=? AND session_id=?",
                (run_id, scope.session_id))
            conn.execute(
                "UPDATE recovery_sessions SET reason_codes_json=?,revision=revision+1 WHERE session_id=?",
                (json.dumps(codes), scope.session_id))

        self.db._execute_write(_tx)
