"""Recovery-only monotonic deadline context; ordinary callers are unaffected."""

from __future__ import annotations

import time
import threading
import sqlite3

import pytest

from hermes_state_recovery_deadline import (
    RecoveryDeadlineExceeded,
    acquire_recovery_lock,
    bounded_sqlite_busy,
    current_deadline,
    recovery_deadline,
    require_time,
)


def test_nested_recovery_context_cannot_extend_outer_deadline() -> None:
    outer = time.monotonic() + 1
    with recovery_deadline(outer):
        assert current_deadline() == outer
        with recovery_deadline(outer + 100):
            assert current_deadline() == outer
        assert current_deadline() == outer
    assert current_deadline() is None


def test_expired_and_nonfinite_deadlines_refuse() -> None:
    for deadline in (float("nan"), float("inf"), float("-inf"), time.monotonic() - 1):
        with pytest.raises(RecoveryDeadlineExceeded):
            with recovery_deadline(deadline):
                require_time()


def test_recovery_lock_wait_expires_without_taking_or_leaking_lock() -> None:
    lock = threading.Lock()
    lock.acquire()
    with recovery_deadline(time.monotonic() + 0.02):
        with pytest.raises(RecoveryDeadlineExceeded):
            with acquire_recovery_lock(lock):
                pytest.fail("deadline must refuse before acquiring")
    lock.release()
    with acquire_recovery_lock(lock):
        assert lock.locked()
    assert not lock.locked()


def test_sqlite_busy_timeout_is_restored_after_failed_recovery_work() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA busy_timeout=1000")
    try:
        with recovery_deadline(time.monotonic() + 0.05):
            with pytest.raises(RuntimeError, match="sentinel"):
                with bounded_sqlite_busy(conn):
                    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 0
                    time.sleep(0.01)
                    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 0
                    raise RuntimeError("sentinel")
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1000
    finally:
        conn.close()
