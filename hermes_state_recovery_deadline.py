"""Optional monotonic deadline for recovery work on shared state.db handles.

The context is entered by a bounded recovery worker. Ordinary SessionDB and
registry callers see None and retain their existing lock/retry behavior.
"""

from __future__ import annotations

import math
import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Protocol


class RecoveryDeadlineExceeded(TimeoutError):
    """The current recovery worker no longer has time for a new operation."""


_deadline: ContextVar[float | None] = ContextVar("recovery_db_deadline", default=None)


class _Lock(Protocol):
    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool: ...
    def release(self) -> None: ...


def current_deadline() -> float | None:
    return _deadline.get()


def require_time() -> float | None:
    """Return remaining seconds, or None outside a recovery worker."""
    deadline = _deadline.get()
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RecoveryDeadlineExceeded("recovery_deadline_exceeded")
    return remaining


@contextmanager
def recovery_deadline(deadline: float) -> Iterator[None]:
    """Apply an absolute finite deadline; nested work can only shorten it."""
    if type(deadline) is not float or not math.isfinite(deadline):
        raise RecoveryDeadlineExceeded("recovery_deadline_invalid")
    outer = _deadline.get()
    token = _deadline.set(min(outer, deadline) if outer is not None else deadline)
    try:
        require_time()
        yield
    finally:
        _deadline.reset(token)


@contextmanager
def acquire_recovery_lock(lock: _Lock) -> Iterator[None]:
    """Take a lock by the active deadline, or normally outside recovery."""
    remaining = require_time()
    acquired = lock.acquire() if remaining is None else lock.acquire(timeout=remaining)
    if not acquired:
        raise RecoveryDeadlineExceeded("recovery_deadline_exceeded")
    try:
        require_time()
        yield
    finally:
        lock.release()


@contextmanager
def bounded_sqlite_busy(conn: sqlite3.Connection) -> Iterator[None]:
    """Disable hidden SQLite waits on one exclusively held recovery connection."""
    if current_deadline() is None:
        yield
        return
    require_time()
    original = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    conn.execute("PRAGMA busy_timeout=0")
    try:
        require_time()
        yield
    finally:
        conn.execute(f"PRAGMA busy_timeout={original}")
