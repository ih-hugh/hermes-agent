"""Recovery DB work obeys one optional deadline across local and SQLite waits."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager

import pytest

import hermes_state_wal
import hermes_state
import hermes_state_recovery_deadline as deadline_module
from agent.recovery_context import (
    AdmissionHandoff,
    current_incarnation,
    issue_producer_permit,
)
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionCompressionInProgressError, SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
)
from hermes_state_recovery_deadline import RecoveryDeadlineExceeded, recovery_deadline
from tests.recovery_provider_fixture import provider_admission


@pytest.fixture
def db(tmp_path):
    handle = SessionDB(db_path=tmp_path / "state.db")
    yield handle
    handle.close()


def _hold_writer_lock(db: SessionDB) -> tuple[threading.Event, threading.Thread]:
    entered = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with db._lock:
            entered.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold)
    thread.start()
    assert entered.wait(timeout=1)
    return release, thread


def test_recovery_write_refuses_held_python_lock_before_callback(db: SessionDB) -> None:
    release, thread = _hold_writer_lock(db)
    callbacks = 0
    try:

        def write(conn: sqlite3.Connection) -> None:
            nonlocal callbacks
            callbacks += 1

        with recovery_deadline(time.monotonic() + 0.03):
            with pytest.raises(RecoveryDeadlineExceeded):
                db._execute_write(write, patience_s=1.0)
        assert callbacks == 0
    finally:
        release.set()
        thread.join(timeout=1)
    row = db._read_one("SELECT 1")
    assert row is not None and row[0] == 1


def test_recovery_read_serializes_on_timed_writer_lock(db: SessionDB) -> None:
    release, thread = _hold_writer_lock(db)
    try:
        with recovery_deadline(time.monotonic() + 0.03):
            with pytest.raises(RecoveryDeadlineExceeded):
                db._read_one("SELECT 1")
    finally:
        release.set()
        thread.join(timeout=1)
    row = db._read_one("SELECT 1")
    assert row is not None and row[0] == 1


def test_recovery_begin_busy_retries_within_budget_and_restores_timeout(
    db: SessionDB,
) -> None:
    with db._lock:
        assert db._conn is not None
        original_busy_ms = db._conn.execute("PRAGMA busy_timeout").fetchone()[0]
    blocker = sqlite3.connect(db.db_path, timeout=0.1, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    began = time.monotonic()
    try:
        with recovery_deadline(began + 0.08):
            with pytest.raises(RecoveryDeadlineExceeded):
                db._execute_write(lambda conn: conn.execute("SELECT 1"), patience_s=1.0)
        assert time.monotonic() - began < 0.8
    finally:
        blocker.rollback()
        blocker.close()
    with db._lock:
        assert db._conn is not None
        assert db._conn.execute("PRAGMA busy_timeout").fetchone()[0] == original_busy_ms


def test_prebegin_sqlite_busy_with_shorter_patience_preserves_busy_error(
    db: SessionDB,
) -> None:
    blocker = sqlite3.connect(db.db_path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    calls = 0

    def callback(conn: sqlite3.Connection) -> None:
        nonlocal calls
        calls += 1

    began = time.monotonic()
    try:
        with recovery_deadline(began + 1.0):
            with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
                db._execute_write(callback, patience_s=0.02)
        assert time.monotonic() - began < 0.30
        assert calls == 0
    finally:
        blocker.rollback()
        blocker.close()


def test_recovery_ioerr_retry_sleep_cannot_extend_deadline(
    db: SessionDB, monkeypatch
) -> None:
    attempts = 0

    @contextmanager
    def transient_ioerr():
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("disk I/O error")
        yield

    monkeypatch.setattr(db, "_read_ctx", transient_ioerr)
    began = time.monotonic()
    with recovery_deadline(began + 0.03):
        with pytest.raises(RecoveryDeadlineExceeded):
            db._read_retrying_ioerr(lambda conn: conn.execute("SELECT 1"))
    assert attempts == 1


def test_expired_recovery_read_converts_sqlite_interrupt_to_deadline(
    db: SessionDB,
) -> None:
    def interrupted(conn: sqlite3.Connection) -> None:
        time.sleep(0.05)
        raise sqlite3.OperationalError("interrupted")

    with recovery_deadline(time.monotonic() + 0.03):
        with pytest.raises(RecoveryDeadlineExceeded):
            db._read_retrying_ioerr(interrupted)


def test_recovery_write_skips_postcommit_maintenance_lock_waits(
    db: SessionDB, monkeypatch
) -> None:
    db._write_count = 49
    db._CHECKPOINT_EVERY_N_WRITES = 50
    db._FTS_MERGE_EVERY_N_WRITES = 50
    monkeypatch.setattr(db, "_try_wal_checkpoint", lambda: time.sleep(0.12))
    monkeypatch.setattr(db, "_try_incremental_merge_fts", lambda: time.sleep(0.12))
    began = time.monotonic()
    with recovery_deadline(began + 0.04):
        result = db._execute_write(lambda conn: "committed", patience_s=1.0)
    assert result == "committed"
    assert time.monotonic() - began < 0.1


def test_late_commit_busy_refuses_before_shared_deadline(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(hermes_state_wal, "resolve_journal_mode", lambda: "delete")
    db = SessionDB(db_path=tmp_path / "state.db")
    blocker = None
    try:
        with db._lock:
            assert db._conn is not None
            db._conn.execute("CREATE TABLE deadline_probe(value INTEGER)")
            db._conn.commit()
            assert db._conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        blocker = sqlite3.connect(db.db_path, isolation_level=None)
        blocker.execute("BEGIN")
        blocker.execute("SELECT * FROM deadline_probe").fetchall()
        writer_sql: list[str] = []
        with db._lock:
            assert db._conn is not None
            db._conn.set_trace_callback(writer_sql.append)
        real_monotonic = time.monotonic
        wall_began = real_monotonic()
        ticks = [100.0]
        monkeypatch.setattr(deadline_module.time, "monotonic", lambda: ticks[0])

        def late_insert(conn: sqlite3.Connection) -> None:
            # Reach SQLite COMMIT with time remaining, independent of host load.
            ticks[0] = 100.16
            conn.execute("INSERT INTO deadline_probe VALUES (1)")

        with recovery_deadline(100.20):
            with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
                db._execute_write(late_insert, patience_s=1.0)
        assert "COMMIT" in writer_sql
        assert real_monotonic() - wall_began < 1.0
        blocker.rollback()
        blocker.close()
        blocker = None
        row = db._read_one("SELECT COUNT(*) FROM deadline_probe")
        assert row is not None and row[0] == 0
    finally:
        if blocker is not None:
            blocker.rollback()
            blocker.close()
        db.close()


def test_late_read_sql_busy_refuses_before_shared_deadline(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(hermes_state_wal, "resolve_journal_mode", lambda: "delete")
    db = SessionDB(db_path=tmp_path / "state.db")
    blocker = None
    try:
        db._execute_write(
            lambda conn: conn.execute("CREATE TABLE deadline_probe(value INTEGER)")
        )
        blocker = sqlite3.connect(db.db_path, isolation_level=None)
        blocker.execute("BEGIN EXCLUSIVE")
        real_monotonic = time.monotonic
        wall_began = real_monotonic()
        ticks = [100.0]
        attempted = 0
        monkeypatch.setattr(deadline_module.time, "monotonic", lambda: ticks[0])

        def late_read(conn: sqlite3.Connection) -> sqlite3.Cursor:
            nonlocal attempted
            attempted += 1
            ticks[0] = 100.16
            return conn.execute("SELECT value FROM deadline_probe")

        with recovery_deadline(100.20):
            with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
                db._read_retrying_ioerr(late_read)
        assert attempted == 1
        assert real_monotonic() - wall_began < 1.0
    finally:
        if blocker is not None:
            blocker.rollback()
            blocker.close()
        db.close()


def test_expired_compression_retry_reports_shared_deadline(db: SessionDB) -> None:
    def transient(conn: sqlite3.Connection) -> None:
        time.sleep(0.04)
        raise SessionCompressionInProgressError("foreign compression")

    with recovery_deadline(time.monotonic() + 0.02):
        with pytest.raises(RecoveryDeadlineExceeded):
            db._execute_write(transient, patience_s=1.0)


def test_shorter_compression_budget_preserves_compression_error(db: SessionDB) -> None:
    db._COMPRESSION_BUSY_WAIT_S = 0.02

    def transient(conn: sqlite3.Connection) -> None:
        raise SessionCompressionInProgressError("foreign compression")

    with recovery_deadline(time.monotonic() + 1.0):
        with pytest.raises(SessionCompressionInProgressError):
            db._execute_write(transient, patience_s=1.0)


class _CommitClockConnection(sqlite3.Connection):
    """Advance a fake deadline clock only after SQLite's actual commit succeeds."""

    advance_after_commit = None

    def commit(self) -> None:
        super().commit()
        if self.advance_after_commit is not None:
            self.advance_after_commit()


def _clocked_db(tmp_path, monkeypatch: pytest.MonkeyPatch) -> SessionDB:
    connect = hermes_state._connect_tracked_db

    def clocked_connect(*args, **kwargs):
        return connect(*args, factory=_CommitClockConnection, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(hermes_state, "_connect_tracked_db", clocked_connect)
        return SessionDB(db_path=tmp_path / "state.db")


def test_successful_late_commit_returns_actual_callback_result(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _clocked_db(tmp_path, monkeypatch)
    try:
        db._execute_write(
            lambda conn: conn.execute("CREATE TABLE late_commit(value TEXT)")
        )
        assert isinstance(db._conn, _CommitClockConnection)
        ticks = [100.0]
        monkeypatch.setattr(deadline_module.time, "monotonic", lambda: ticks[0])
        db._conn.advance_after_commit = lambda: ticks.__setitem__(0, 101.0)
        marker = object()
        with recovery_deadline(100.5):
            result = db._execute_write(
                lambda conn: (
                    conn.execute("INSERT INTO late_commit VALUES('saved')"),
                    marker,
                )[1]
            )
        assert result is marker
        row = db._read_one("SELECT value FROM late_commit")
        assert row is not None and row[0] == "saved"
    finally:
        db.close()


def test_precommit_expiry_still_rolls_back_without_result(
    db: SessionDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    db._execute_write(lambda conn: conn.execute("CREATE TABLE precommit(value TEXT)"))
    ticks = [100.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: ticks[0])

    def write(conn: sqlite3.Connection) -> str:
        conn.execute("INSERT INTO precommit VALUES('rolled back')")
        ticks[0] = 101.0
        return "uncommitted"

    with recovery_deadline(100.5):
        with pytest.raises(RecoveryDeadlineExceeded):
            db._execute_write(write)
    assert db._read_one("SELECT value FROM precommit") is None


def test_late_reserve_commit_retains_one_use_handoff(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = _clocked_db(tmp_path, monkeypatch)
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "default", "a" * 64, "late-reserve")
    try:
        assert isinstance(db._conn, _CommitClockConnection)
        ticks = [100.0]
        monkeypatch.setattr(deadline_module.time, "monotonic", lambda: ticks[0])
        db._conn.advance_after_commit = lambda: ticks.__setitem__(0, 101.0)
        with recovery_deadline(100.5):
            result = store.reserve(
                RecoveryAdmission(
                    schema="hermes.recovery/v1", generation=0, parent_run_id=None
                ),
                AdmissionIdentity(
                    scope,
                    "byf-recovery-v1:late",
                    "b" * 64,
                    "run_late",
                    current_incarnation(),
                    provider_admission(scope.session_id),
                ),
            )
        assert result.outcome == "created"
        assert isinstance(result.handoff, AdmissionHandoff)
        replay = store.lookup_key(scope, "byf-recovery-v1:late", "b" * 64)
        assert replay is not None and replay.outcome == "replayed"
        assert issue_producer_permit(store, result.handoff) is not None
        with pytest.raises(RecoveryRefused, match="admission_handoff_consumed"):
            issue_producer_permit(store, result.handoff)
    finally:
        db.close()
