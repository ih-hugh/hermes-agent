"""Raw async delegation refuses protected stores before schema or worker effects."""

from __future__ import annotations

import sqlite3

import pytest

from hermes_state_recovery import RecoveryRefused
from tools import async_delegation as ad


def _protected(path):
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE recovery_sessions(session_id TEXT PRIMARY KEY, phase TEXT, root_run_id TEXT)")
        conn.execute("CREATE TABLE recovery_members(run_id TEXT PRIMARY KEY, session_id TEXT, producer_state TEXT)")
        conn.execute("INSERT INTO recovery_sessions VALUES('protected', 'sealed', 'run')")
        conn.execute("INSERT INTO recovery_members VALUES('run', 'protected', 'closed')")


def test_raw_connect_refuses_before_schema_or_backup_effect(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    _protected(path)
    monkeypatch.setattr(ad, "_db_path", lambda: path)
    with pytest.raises(RecoveryRefused):
        ad._connect()
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is None


def test_same_connection_gate_refuses_before_reconciliation(tmp_path):
    path = tmp_path / "state.db"
    _protected(path)
    with sqlite3.connect(path) as conn:
        with pytest.raises(RecoveryRefused):
            ad._initialize_schema(conn)
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is None
        assert conn.execute("SELECT recovery_row_guard('protected', 'message')").fetchone()[0] == 0


def test_dispatch_rejects_before_record_or_executor(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    _protected(path)
    monkeypatch.setattr(ad, "_db_path", lambda: path)
    monkeypatch.setattr(ad, "_get_executor", lambda *_: pytest.fail("worker pool started"))
    ad._reset_for_tests()
    handle = ad.dispatch_async_delegation(
        goal="background", context=None, toolsets=None, role="worker", model=None,
        session_key="key", parent_session_id="protected",
        runner=lambda: pytest.fail("runner started"))
    assert handle["status"] == "rejected"
    assert ad.active_count() == 0
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is None


def test_raw_connect_creates_only_genuinely_absent_ordinary_store(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setattr(ad, "_db_path", lambda: path)
    conn = ad._connect()
    try:
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is not None
    finally:
        conn.close()
    assert path.exists()


def test_raw_connect_leaves_unreadable_existing_store_untouched(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    path.write_bytes(b"not a sqlite database")
    before = set(tmp_path.iterdir())
    monkeypatch.setattr(ad, "_db_path", lambda: path)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        ad._connect()
    assert path.read_bytes() == b"not a sqlite database"
    assert set(tmp_path.iterdir()) == before
