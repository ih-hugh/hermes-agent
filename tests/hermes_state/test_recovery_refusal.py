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


def _catalog(path, *, phase="open", member_state="open"):
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE recovery_store(singleton INTEGER, store_id TEXT);
            CREATE TABLE recovery_sessions(session_id TEXT PRIMARY KEY, profile TEXT,
                scope_digest TEXT, phase TEXT, revision INTEGER, root_run_id TEXT);
            CREATE TABLE recovery_members(run_id TEXT PRIMARY KEY, session_id TEXT,
                generation INTEGER, producer_state TEXT);
            CREATE TABLE recovery_producers(producer_id TEXT, run_id TEXT, kind TEXT,
                state TEXT, parent_producer_id TEXT);
            CREATE TABLE recovery_root_done(run_id TEXT);
            CREATE TABLE recovery_sends(attempt_id TEXT, run_id TEXT, producer_id TEXT,
                sequence INTEGER, state TEXT, delta_id TEXT);
            CREATE TABLE recovery_usage_slots(delta_id TEXT, attempt_id TEXT, state TEXT);
            CREATE TABLE recovery_write_acks(write_id TEXT, session_id TEXT, run_id TEXT,
                generation INTEGER, mutation TEXT, state TEXT);
            CREATE TABLE recovery_provider_admissions(session_id TEXT, provider TEXT,
                hermes_revision TEXT, source_sha256 TEXT, provider_sha256 TEXT,
                lease_id TEXT, grant_sha256 TEXT, admission_json TEXT, admission_sha256 TEXT);
            CREATE TABLE recovery_provider_invocations(invocation_id TEXT, session_id TEXT,
                run_id TEXT, generation INTEGER, producer_id TEXT, sequence INTEGER,
                kind TEXT, state TEXT, create_invocation_id TEXT, container_id TEXT,
                container_attestation_sha256 TEXT, exit_code INTEGER, outcome_reason TEXT);
        """)
        conn.execute("INSERT INTO recovery_sessions VALUES('protected', '', '', ?, 0, 'run')", (phase,))
        conn.execute("INSERT INTO recovery_members VALUES('run', 'protected', 0, ?)", (member_state,))


@pytest.mark.parametrize("phase", ["open", "closing", "sealed"])
@pytest.mark.parametrize("member_state", ["open", "closed", "incomplete"])
def test_exact_durable_identity_refuses_in_every_phase(tmp_path, phase, member_state):
    path = tmp_path / "state.db"
    _catalog(path, phase=phase, member_state=member_state)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_session("protected", db_path=path)
    require_unprotected_session("ordinary", db_path=path)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_store(db_path=path)


def test_readonly_probe_uses_escaped_exact_path_and_never_creates_store(tmp_path):
    path = tmp_path / "state?#%.db"
    _catalog(path)
    with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
        require_unprotected_session("protected", db_path=path)
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
        conn.execute("DELETE FROM recovery_sessions WHERE session_id='protected'")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("protected", db_path=path)
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
        conn.execute("CREATE TRIGGER recovery_guard_recovery_sessions_insert "
                     "BEFORE INSERT ON recovery_sessions BEGIN SELECT 1; END")
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
