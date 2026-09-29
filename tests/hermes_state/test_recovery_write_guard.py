"""Protected recovery rows refuse writes without in-transaction authority."""

from __future__ import annotations

import sqlite3
import hashlib
import json
from pathlib import Path

import pytest

from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from agent.recovery_context import (
    bind_write_permit,
    current_incarnation,
    issue_producer_permit,
    issue_write_permit,
)
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore
from hermes_state_recovery import RecoveryRefused
from hermes_state_repair import _copy_database_snapshot
from hermes_state_recovery_guard import guarded_write


def _protected_db(
    tmp_path: Path,
) -> tuple[SessionDB, RecoveryStore, RecoveryScope, object]:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:one", "a" * 64, "root", current_incarnation()
        ),
    )
    assert admitted.outcome == "created"
    return db, store, scope, admitted.handoff


def test_admission_atomically_guards_protected_rows_but_preserves_legacy_writes(
    tmp_path: Path,
) -> None:
    db, store, scope, _ = _protected_db(tmp_path)
    try:
        db.create_session("ordinary-session", "cli")
        assert db.get_session("ordinary-session") is not None

        with pytest.raises(sqlite3.DatabaseError):
            db.create_session(scope.session_id, "api_server")
        assert db.get_session(scope.session_id) is None

        with sqlite3.connect(db.db_path) as raw:
            with pytest.raises(sqlite3.DatabaseError):
                raw.execute(
                    "INSERT INTO sessions(id, source) VALUES(?, ?)",
                    (scope.session_id, "api_server"),
                )
            with pytest.raises(sqlite3.DatabaseError):
                raw.execute(
                    "UPDATE sessions SET display_name=? WHERE id=?",
                    ("raw", "ordinary-session"),
                )
        assert (
            db._read_one(
                "SELECT phase FROM recovery_sessions WHERE session_id=?",
                (scope.session_id,),
            )[0]
            == "open"
        )
    finally:
        db.close()


def test_non_opted_profile_has_no_recovery_triggers(tmp_path: Path) -> None:
    db = SessionDB(tmp_path / "ordinary.db")
    try:
        db.create_session("ordinary", "cli")
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "UPDATE sessions SET display_name=? WHERE id=?", ("raw", "ordinary")
            )
        assert db.get_session("ordinary")["display_name"] == "raw"
    finally:
        db.close()


def test_reopened_sessiondb_has_guard_before_first_write(tmp_path: Path) -> None:
    db, _, scope, _ = _protected_db(tmp_path)
    path = db.db_path
    db.close()
    reopened = SessionDB(path)
    try:
        reopened.create_session("ordinary", "cli")
        with pytest.raises(sqlite3.DatabaseError):
            reopened.create_session(scope.session_id, "api_server")
        assert reopened.get_session(scope.session_id) is None
    finally:
        reopened.close()


def test_guarded_transcript_ack_prevents_duplicate_after_lost_response(
    tmp_path: Path,
) -> None:
    db, store, scope, handoff = _protected_db(tmp_path)
    try:
        producer = issue_producer_permit(store, handoff)
        writer = issue_write_permit(producer, store, scope, "root", 0)
        with bind_write_permit(writer):
            db.create_session(scope.session_id, "api_server")
        rows = [{"role": "user", "content": "one"}]
        digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        assert (
            db.append_messages_batch(
                scope.session_id,
                rows,
                recovery_permit=writer,
                recovery_write_id="batch-1",
                recovery_payload_sha256=digest,
            )
            == 1
        )
        assert db.read_write_ack(scope, "batch-1").state == "committed"
        # A committed SQLite write can outlive a lost caller response. Its exact
        # retry must read the ack instead of appending the transcript again.
        assert (
            db.append_messages_batch(
                scope.session_id,
                rows,
                recovery_permit=writer,
                recovery_write_id="batch-1",
                recovery_payload_sha256=digest,
            )
            == 1
        )
        assert len(db.get_messages(scope.session_id)) == 1
        # Equal content in a later logical operation still appends. The caller
        # retains the first operation ID only until that batch is acknowledged.
        assert (
            db.append_messages_batch(
                scope.session_id,
                [{"role": "user", "content": "one"}],
                recovery_permit=writer,
                recovery_write_id="batch-2",
                recovery_payload_sha256=digest,
            )
            == 1
        )
        assert len(db.get_messages(scope.session_id)) == 2
        with pytest.raises(RecoveryRefused):
            db.append_messages_batch(
                scope.session_id,
                [{"role": "user", "content": "changed"}],
                recovery_permit=writer,
                recovery_write_id="batch-1",
                recovery_payload_sha256="f" * 64,
            )
        store.close_producer(scope, "root", producer)
        assert db.read_write_ack(scope, "batch-1").state == "committed"
        assert (
            db.append_messages_batch(
                scope.session_id,
                rows,
                recovery_permit=writer,
                recovery_write_id="batch-1",
                recovery_payload_sha256=digest,
            )
            == 1
        )
    finally:
        db.close()


def test_failed_guarded_batch_keeps_a_durable_negative_ack(tmp_path: Path) -> None:
    db, store, scope, handoff = _protected_db(tmp_path)
    try:
        producer = issue_producer_permit(store, handoff)
        writer = issue_write_permit(producer, store, scope, "root", 0)
        with bind_write_permit(writer):
            db.create_session(scope.session_id, "api_server")

        def _fail(_conn):
            raise RuntimeError("disk write failed")

        with pytest.raises(RuntimeError):
            guarded_write(db, writer, "message", "failed-batch", "c" * 64, _fail)
        assert db.read_write_ack(scope, "failed-batch").state == "failed"
        assert (
            "untracked_write"
            in db._read_one(
                "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
                (scope.session_id,),
            )[0]
        )
    finally:
        db.close()


def test_unpersistable_failure_keeps_pending_batch_and_member_open(
    tmp_path: Path,
) -> None:
    db, store, scope, handoff = _protected_db(tmp_path)
    try:
        producer = issue_producer_permit(store, handoff)
        writer = issue_write_permit(producer, store, scope, "root", 0)
        with bind_write_permit(writer):
            db.create_session(scope.session_id, "api_server")
        db._write_sql(
            "CREATE TRIGGER deny_failure BEFORE UPDATE OF state ON recovery_write_acks "
            "WHEN NEW.state='failed' BEGIN SELECT RAISE(FAIL, 'failure write unavailable'); END"
        )

        def _fail(_conn):
            raise RuntimeError("message write failed")

        with pytest.raises(RuntimeError):
            guarded_write(db, writer, "message", "pending-batch", "d" * 64, _fail)
        assert db.read_write_ack(scope, "pending-batch").state == "pending"
        store.close_producer(scope, "root", producer)
        assert (
            db._read_one(
                "SELECT producer_state FROM recovery_members WHERE run_id='root'"
            )[0]
            == "open"
        )
    finally:
        db.close()


def test_repair_backup_refuses_protected_store_before_creating_destination(
    tmp_path: Path,
) -> None:
    db, _, _, _ = _protected_db(tmp_path)
    destination = tmp_path / "repair-copy.db"
    try:
        with pytest.raises(sqlite3.DatabaseError):
            _copy_database_snapshot(db.db_path, destination)
        assert not destination.exists()
    finally:
        db.close()


def test_bound_permit_guards_old_and_new_session_ids(tmp_path: Path) -> None:
    db, store, scope, handoff = _protected_db(tmp_path)
    try:
        producer = issue_producer_permit(store, handoff)
        writer = issue_write_permit(producer, store, scope, "root", 0)
        with bind_write_permit(writer):
            db.create_session(scope.session_id, "api_server")
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db.append_message(scope.session_id, "user", "unacknowledged")
        protected_rows = [{"role": "user", "content": "protected"}]
        protected_digest = hashlib.sha256(
            json.dumps(protected_rows, sort_keys=True).encode()
        ).hexdigest()
        db.append_messages_batch(
            scope.session_id,
            protected_rows,
            recovery_permit=writer,
            recovery_write_id="protected-message",
            recovery_payload_sha256=protected_digest,
        )
        protected_message = db.get_messages(scope.session_id)[0]["id"]
        db.create_session("ordinary-session", "cli")
        ordinary_message = db.append_message("ordinary-session", "user", "ordinary")

        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE sessions SET id=? WHERE id=?",
                (scope.session_id, "ordinary-session"),
            )
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE sessions SET id=? WHERE id=?", ("renamed", scope.session_id)
            )
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql("DELETE FROM sessions WHERE id=?", (scope.session_id,))
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "DELETE FROM recovery_sessions WHERE session_id=?", (scope.session_id,)
            )
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE messages SET session_id=? WHERE id=?",
                (scope.session_id, ordinary_message),
            )
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE messages SET session_id=? WHERE id=?",
                ("ordinary-session", protected_message),
            )
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql("DELETE FROM messages WHERE id=?", (protected_message,))

        assert db.get_session(scope.session_id) is not None
        assert db.get_session("ordinary-session") is not None
        with bind_write_permit(writer):
            db._write_sql(
                "UPDATE sessions SET last_activity_description=? WHERE id=?",
                ("approved", scope.session_id),
            )
        assert (
            db.get_session(scope.session_id)["last_activity_description"] == "approved"
        )
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE sessions SET title=? WHERE id=?", ("title", scope.session_id)
            )
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db.update_token_counts(
                scope.session_id, input_tokens=9, model="model-x", api_call_count=1
            )
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db._write_sql("DELETE FROM sessions WHERE id=?", (scope.session_id,))
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE sessions SET id=? WHERE id=?", ("renamed", scope.session_id)
            )
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db._write_sql("DELETE FROM messages WHERE id=?", (protected_message,))
        assert db.get_session(scope.session_id)["input_tokens"] == 0
        store.close_producer(scope, "root", producer)
        with bind_write_permit(writer), pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "UPDATE sessions SET last_activity_description=? WHERE id=?",
                ("late", scope.session_id),
            )
        assert (
            db.get_session(scope.session_id)["last_activity_description"] == "approved"
        )
    finally:
        db.close()
