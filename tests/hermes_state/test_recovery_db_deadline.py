"""Recovery DB work obeys one optional deadline across local and SQLite waits."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager

import pytest

import hermes_state_wal
from hermes_state import SessionCompressionInProgressError, SessionDB
from hermes_state_recovery_deadline import RecoveryDeadlineExceeded, recovery_deadline


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
        began = time.monotonic()
        with recovery_deadline(began + 0.20):
            with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
                db._execute_write(
                    lambda conn: (
                        time.sleep(0.16),
                        conn.execute("INSERT INTO deadline_probe VALUES (1)"),
                    ),
                    patience_s=1.0,
                )
        assert time.monotonic() - began < 0.30
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
        began = time.monotonic()
        with recovery_deadline(began + 0.20):
            with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
                db._read_retrying_ioerr(
                    lambda conn: (
                        time.sleep(0.16),
                        conn.execute("SELECT value FROM deadline_probe"),
                    )[1]
                )
        assert time.monotonic() - began < 0.30
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
