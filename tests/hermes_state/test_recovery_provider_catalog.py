"""Provider tables participate in the protected catalog and SQL guard inventory."""

from __future__ import annotations

import sqlite3

import pytest

from agent.recovery_context import _store_writer
from hermes_recovery_refusal import require_unprotected_session
from hermes_state import SessionDB
from hermes_state_recovery import RecoveryRefused
from hermes_state_recovery_guard import _LEDGER, install_recovery_guards


def test_provider_tables_and_raw_guards_are_complete(tmp_path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    try:
        assert {"recovery_provider_admissions", "recovery_provider_invocations"} <= set(_LEDGER)
        require_unprotected_session("unprotected", db_path=path)

        def install(conn):
            with _store_writer(db, conn):
                install_recovery_guards(conn)

        db._execute_write(install)
        with sqlite3.connect(path) as foreign:
            with pytest.raises(sqlite3.DatabaseError):
                foreign.execute("INSERT INTO recovery_provider_admissions"
                                "(session_id,provider,hermes_revision,source_sha256,provider_sha256,"
                                "lease_id,grant_sha256,admission_json,admission_sha256)"
                                " VALUES('x','byf_workspace','x','x','x','x','x',X'01','x')")
        require_unprotected_session("unprotected", db_path=path)
    finally:
        db.close()


def test_partial_provider_catalog_refuses_before_repair(tmp_path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    db.close()
    with sqlite3.connect(path) as foreign:
        foreign.execute("DROP TABLE recovery_provider_invocations")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        require_unprotected_session("unprotected", db_path=path)
