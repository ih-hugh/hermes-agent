"""The new immutable seal tables remain part of strict protected authority."""

from __future__ import annotations

import sqlite3

import pytest

from agent.recovery_context import current_incarnation
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_recovery_refusal import require_compatible_recovery_connection
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore
from tests.recovery_provider_fixture import provider_admission


def test_immutable_seal_catalog_and_store_writer(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "seal-catalog")
    try:
        created = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=0, parent_run_id=None
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:catalog",
                "a" * 64,
                "root",
                current_incarnation(),
                provider_admission(scope.session_id),
            ),
        )
        assert created.outcome == "created"
        with sqlite3.connect(db.db_path) as probe:
            require_compatible_recovery_connection(probe)

        def insert(conn):
            conn.execute(
                "INSERT INTO recovery_seal_documents VALUES(?,?,?,?,?)",
                (scope.session_id, b"result", b"receipt", "c" * 64, 1),
            )
            conn.execute(
                "INSERT INTO recovery_sealed_pages VALUES(?,?,?)",
                (scope.session_id, 0, b"page"),
            )

        store._write(insert)
        for table, key in (
            ("recovery_seal_documents", "result_json"),
            ("recovery_sealed_pages", "page_bytes"),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="recovery_immutable_seal"):
                store._write(
                    lambda conn: conn.execute(
                        f"UPDATE {table} SET {key}=? WHERE session_id=?",
                        (b"mutated", scope.session_id),
                    )
                )
            with pytest.raises(sqlite3.IntegrityError, match="recovery_immutable_seal"):
                store._write(
                    lambda conn: conn.execute(
                        f"DELETE FROM {table} WHERE session_id=?",
                        (scope.session_id,),
                    )
                )
    finally:
        db.close()
