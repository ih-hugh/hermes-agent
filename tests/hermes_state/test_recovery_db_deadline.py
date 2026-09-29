"""Recovery DB work obeys one optional deadline across local and SQLite waits."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager

import pytest

from hermes_state import SessionDB
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


def test_recovery_sqlite_busy_wait_uses_remaining_budget_and_restores(
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
