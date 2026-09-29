"""Read-only refusal probes for unsupported protected entrypoints."""

from __future__ import annotations

import sqlite3

import pytest

from hermes_recovery_refusal import (
    readonly_declared_session,
    readonly_resume_session,
    require_unprotected_session,
    require_unprotected_store,
)
from hermes_state_recovery import RecoveryRefused
from tests.hermes_state.test_recovery_write_guard import _protected_db


def _catalog(path, *, phase="open", member_state="open"):
    db, store, scope, _ = _protected_db(path.parent)
    try:
        def _set_state(conn):
            conn.execute(
                "UPDATE recovery_sessions SET phase=? WHERE session_id=?",
                (phase, scope.session_id),
            )
            conn.execute(
                "UPDATE recovery_members SET producer_state=? WHERE run_id='root'",
                (member_state,),
            )

        store._write(_set_state)
    finally:
        db.close()
    if path.name != "state.db":
        (path.parent / "state.db").rename(path)


@pytest.mark.parametrize("phase", ["open", "closing", "sealed"])
@pytest.mark.parametrize("member_state", ["open", "closed", "incomplete"])
def test_exact_durable_identity_refuses_in_every_phase(tmp_path, phase, member_state):
    path = tmp_path / "state.db"
    _catalog(path, phase=phase, member_state=member_state)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_session("protected-session", db_path=path)
    require_unprotected_session("ordinary", db_path=path)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_store(db_path=path)


def test_readonly_probe_uses_escaped_exact_path_and_never_creates_store(tmp_path):
    path = tmp_path / "state?#%.db"
    _catalog(path)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_session("protected-session", db_path=path)
    absent = tmp_path / "absent?#%.db"
    require_unprotected_session("ordinary", db_path=absent)
    assert not absent.exists()


def test_readonly_alias_resolution_uses_escaped_exact_path(tmp_path):
    from hermes_state import SessionDB

    path = tmp_path / "state?#%.db"
    db = SessionDB(path)
    try:
        db.create_session("exact", source="api_server", session_key="route-key")
    finally:
        db.close()

    assert readonly_declared_session("route-key", db_path=path) == "exact"
    assert readonly_resume_session("exact", db_path=path) == "exact"
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("shape", ["corrupt", "partial", "directory"])
def test_existing_unclassifiable_store_refuses_without_mutation(tmp_path, shape):
    path = tmp_path / "state.db"
    if shape == "corrupt":
        path.write_bytes(b"not sqlite")
    elif shape == "partial":
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE recovery_sessions(session_id TEXT PRIMARY KEY, phase TEXT)")
    else:
        path.mkdir()
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=path)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_store(db_path=path)


def test_ordinary_legacy_store_is_read_without_schema_migration(tmp_path):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE ordinary(id TEXT)")
    require_unprotected_session("ordinary", db_path=path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
            ("ordinary",)]


def test_orphan_member_and_surviving_usage_ledger_are_not_ordinary(tmp_path):
    path = tmp_path / "state.db"
    _catalog(path)
    with sqlite3.connect(path) as conn:
        # Deliberately forge an orphan through the exact ledger guard. This
        # simulates corrupt historical authority, not a normal state transition.
        conn.create_function("recovery_store_guard", 0, lambda: 1)
        conn.execute("DELETE FROM recovery_sessions WHERE session_id='protected-session'")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("protected-session", db_path=path)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_store(db_path=path)

    partial = tmp_path / "surviving-ledger.db"
    with sqlite3.connect(partial) as conn:
        conn.execute("CREATE TABLE recovery_usage_slots(delta_id TEXT)")
        conn.execute("INSERT INTO recovery_usage_slots VALUES('delta')")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=partial)


@pytest.mark.parametrize("table", ["recovery_future_authority", "recovery_sessions"])
def test_unknown_empty_recovery_catalog_is_not_legacy(tmp_path, table):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute(f"CREATE TABLE {table}(id TEXT)")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=path)


def test_known_catalog_with_missing_authority_column_is_unknown(tmp_path):
    path = tmp_path / "state.db"
    _catalog(path)
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE recovery_sends RENAME TO saved_recovery_sends")
        conn.execute("CREATE TABLE recovery_sends(attempt_id TEXT)")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=path)


def test_partial_guard_trigger_inventory_is_unknown(tmp_path):
    path = tmp_path / "state.db"
    _catalog(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER recovery_guard_recovery_sessions_insert")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=path)


@pytest.mark.parametrize("kind", ["view", "index"])
def test_unknown_recovery_catalog_object_is_not_legacy(tmp_path, kind):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as conn:
        if kind == "view":
            conn.execute("CREATE VIEW recovery_future_authority AS SELECT 1 AS protected")
        else:
            conn.execute("CREATE TABLE ordinary(id TEXT)")
            conn.execute("CREATE INDEX recovery_future_authority ON ordinary(id)")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("ordinary", db_path=path)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_store(db_path=path)
