"""Read-only pre-effect refusal for entrypoints outside protected recovery.

This probes the selected profile's existing state.db directly. It never opens a
SessionDB, initializes schema, or grants recovery authority.
"""

from __future__ import annotations

import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from hermes_state_recovery_guard import _LEDGER, _ROWS
from hermes_state_recovery import RecoveryRefused

_AUTHORITY_TABLES = frozenset(_LEDGER)
_GUARD_TRIGGERS = frozenset(
    f"recovery_guard_{table}_{operation}"
    for table in (*_ROWS, *_LEDGER)
    for operation in ("insert", "update", "delete")
)
_REQUIRED_COLUMNS = {
    "recovery_store": {"singleton", "store_id"},
    "recovery_sessions": {"session_id", "profile", "scope_digest", "phase", "revision", "root_run_id"},
    "recovery_members": {"run_id", "session_id", "generation", "producer_state"},
    "recovery_producers": {"producer_id", "run_id", "kind", "state", "parent_producer_id"},
    "recovery_root_done": {"run_id"},
    "recovery_sends": {"attempt_id", "run_id", "producer_id", "sequence", "state", "delta_id"},
    "recovery_usage_slots": {"delta_id", "attempt_id", "state"},
    "recovery_write_acks": {"write_id", "session_id", "run_id", "generation", "mutation", "state"},
}


def _path(db_path: Path | None) -> Path:
    if db_path is not None:
        return Path(db_path)
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "state.db"


def _check_catalog(conn: sqlite3.Connection, session_ids: tuple[str, ...] | None) -> None:
    try:
        rows = conn.execute(
            "SELECT type,name FROM sqlite_master WHERE "
            "(type='table' AND name GLOB 'recovery_*') OR "
            "(type='trigger' AND name GLOB 'recovery_*')"
        ).fetchall()
        tables = {name for kind, name in rows if kind == "table"}
        triggers = {name for kind, name in rows if kind == "trigger"}
        has_guards = any(name.startswith("recovery_guard_") for name in triggers)
        if not tables:
            if triggers:
                raise RecoveryRefused("protected_session_authority_unavailable")
            return  # A valid legacy SQLite store has never published recovery authority.
        if tables != _AUTHORITY_TABLES:
            raise RecoveryRefused("protected_session_authority_unavailable")
        for table, required in _REQUIRED_COLUMNS.items():
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            if not required <= columns:
                raise RecoveryRefused("protected_session_authority_unavailable")
        if session_ids is None:
            protected = has_guards or any(conn.execute(
                f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
                for table in _AUTHORITY_TABLES - {"recovery_store"} if table in tables)
        else:
            protected = any(conn.execute(
                "SELECT 1 FROM recovery_sessions WHERE session_id=? LIMIT 1", (sid,)
            ).fetchone() is not None for sid in session_ids)
            if not protected and any(conn.execute(
                "SELECT 1 FROM recovery_members WHERE session_id=? LIMIT 1", (sid,)
            ).fetchone() is not None for sid in session_ids):
                raise RecoveryRefused("protected_session_authority_unavailable")
        if protected:
            raise RecoveryRefused("protected_session_dispatch")
        if triggers and triggers != _GUARD_TRIGGERS:
            raise RecoveryRefused("protected_session_authority_unavailable")
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc


def _probe(session_ids: tuple[str, ...] | None, db_path: Path | None) -> None:
    path = _path(db_path)
    try:
        identity = path.lstat()
    except FileNotFoundError:
        return  # Genuine absent store: ordinary first-use creation remains available.
    except OSError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    if not stat.S_ISREG(identity.st_mode):
        raise RecoveryRefused("protected_session_authority_unavailable")
    try:
        with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)) as conn:
            conn.execute("PRAGMA query_only=ON")
            _check_catalog(conn, session_ids)
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc


def require_unprotected_session(*session_ids: str, db_path: Path | None = None) -> None:
    """Reject a durable protected identity, including closed and sealed tombstones."""
    identities = tuple(dict.fromkeys(sid for sid in session_ids if isinstance(sid, str) and sid))
    if not identities:
        raise RecoveryRefused("protected_session_authority_unavailable")
    _probe(identities, db_path)


def require_unprotected_store(*, db_path: Path | None = None) -> None:
    """Reject a raw writer whose entire store may contain protected authority."""
    _probe(None, db_path)


def require_unprotected_connection(conn: sqlite3.Connection) -> None:
    """Same-connection gate for raw schema reconciliation, before its first DDL."""
    _check_catalog(conn, None)
