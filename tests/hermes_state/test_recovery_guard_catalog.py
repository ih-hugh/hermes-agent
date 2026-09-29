"""Installed recovery guard SQL is an exact authority catalog, not a name hint."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent.recovery_context import current_incarnation
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
)
from hermes_state_recovery_seal import finalize, read_seal_bytes, read_sealed_page_bytes
from tests.hermes_state.test_recovery_seal import _case, _close
from tests.hermes_state.test_recovery_write_guard import _protected_db
from tests.recovery_provider_fixture import provider_admission


_OLD_IMMUTABLE_BRANCH = (
    "WHEN OLD.source IS NOT NEW.source OR "
    "OLD.profile_name IS NOT NEW.profile_name OR "
    "OLD.started_at IS NOT NEW.started_at OR "
    "OLD.system_prompt IS NOT NEW.system_prompt THEN 'unsupported' "
)
_EXCLUSION_GUARDS = {
    "recovery_guard_recovery_exclusions_insert",
    "recovery_guard_recovery_exclusions_update",
    "recovery_guard_recovery_exclusions_delete",
}


def _catalog_rows(path: Path) -> tuple[tuple[str, str], ...]:
    with sqlite3.connect(path) as conn:
        return tuple(
            conn.execute(
                "SELECT name,sql FROM sqlite_master WHERE name GLOB 'recovery_guard_*' ORDER BY name"
            )
        )


def _make_old_update_body(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='recovery_guard_sessions_update'"
        ).fetchone()
        assert row is not None
        current = row[0]
        assert current.count(_OLD_IMMUTABLE_BRANCH) == 2
        stale = current.replace(_OLD_IMMUTABLE_BRANCH, "")
        conn.execute("DROP TRIGGER recovery_guard_sessions_update")
        conn.execute(stale)


def _source_row(path: Path, session_id: str) -> tuple[object, ...]:
    with sqlite3.connect(path) as conn:
        return tuple(
            conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        )


def test_stale_same_name_source_guard_refuses_protected_reopen_without_mutation(
    tmp_path: Path,
):
    db, _, scope, _ = _protected_db(tmp_path)
    path = db.db_path
    db.close()
    _make_old_update_body(path)
    before_guard = _catalog_rows(path)
    before_source = _source_row(path, scope.session_id)
    with pytest.raises(
        RecoveryRefused, match="protected_session_authority_unavailable"
    ):
        SessionDB(path)
    assert _catalog_rows(path) == before_guard
    assert _source_row(path, scope.session_id) == before_source
    assert not list(tmp_path.glob("state.db.malformed-backup-*"))


def test_live_handle_new_root_refuses_stale_guard_before_admission(tmp_path: Path):
    db, store, first, _ = _protected_db(tmp_path)
    try:
        _make_old_update_body(db.db_path)
        before = db._read_one("SELECT count(*) FROM recovery_sessions")[0]
        second = RecoveryScope(
            store.store_id, first.profile, first.scope_digest, "second-session"
        )
        with pytest.raises(
            RecoveryRefused, match="protected_session_authority_unavailable"
        ):
            store.reserve(
                RecoveryAdmission(
                    schema="hermes.recovery/v1", generation=0, parent_run_id=None
                ),
                AdmissionIdentity(
                    second,
                    "byf-recovery-v1:second",
                    "c" * 64,
                    "second-run",
                    current_incarnation(),
                    provider_admission(second.session_id),
                ),
            )
        assert db._read_one("SELECT count(*) FROM recovery_sessions")[0] == before
        assert (
            db._read_one("SELECT 1 FROM sessions WHERE id=?", (second.session_id,))
            is None
        )
    finally:
        db.close()


@pytest.mark.parametrize("change", ["missing", "extra", "altered_ledger", "no_guards"])
def test_incomplete_or_altered_protected_guards_refuse_reopen(
    tmp_path: Path, change: str
):
    db, _, scope, _ = _protected_db(tmp_path)
    path = db.db_path
    db.close()
    with sqlite3.connect(path) as conn:
        if change == "missing":
            conn.execute("DROP TRIGGER recovery_guard_sessions_update")
        elif change == "extra":
            conn.execute(
                "CREATE TRIGGER recovery_guard_extra BEFORE UPDATE ON sessions "
                "BEGIN SELECT 1; END"
            )
        elif change == "altered_ledger":
            conn.execute("DROP TRIGGER recovery_guard_recovery_write_acks_update")
            conn.execute(
                "CREATE TRIGGER recovery_guard_recovery_write_acks_update "
                "BEFORE UPDATE ON recovery_write_acks BEGIN SELECT 1; END"
            )
        else:
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'recovery_guard_*'"
            ).fetchall():
                if name not in _EXCLUSION_GUARDS:
                    conn.execute(f"DROP TRIGGER {name}")
    before_guard = _catalog_rows(path)
    before_source = _source_row(path, scope.session_id)
    with pytest.raises(
        RecoveryRefused, match="protected_session_authority_unavailable"
    ):
        SessionDB(path)
    assert _catalog_rows(path) == before_guard
    assert _source_row(path, scope.session_id) == before_source


def test_never_opted_full_catalog_with_ordinary_claim_admits_first_root(tmp_path: Path):
    from hermes_state_recovery_exclusions import claim_ordinary_sessions

    path = tmp_path / "state.db"
    ordinary = SessionDB(path)
    ordinary.create_session("ordinary", "cli")
    claim_ordinary_sessions(path, ("ordinary",))
    ordinary.close()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM recovery_sessions").fetchone()[0] == 0
        assert {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'recovery_guard_*'"
            )
        } == _EXCLUSION_GUARDS
    reopened = SessionDB(path)
    try:
        store = RecoveryStore(reopened)
        scope = RecoveryScope(store.store_id, "factory", "b" * 64, "new-root")
        accepted = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=0, parent_run_id=None
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:new-root",
                "d" * 64,
                "root",
                current_incarnation(),
                provider_admission(scope.session_id),
            ),
        )
        assert accepted.outcome == "created"
        assert reopened.get_session("ordinary") is not None
        assert len(_catalog_rows(path)) > len(_EXCLUSION_GUARDS)
    finally:
        reopened.close()


def test_oversized_same_name_guard_sql_refuses_before_body_fetch(tmp_path: Path):
    db, _, scope, _ = _protected_db(tmp_path)
    path = db.db_path
    db.close()
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER recovery_guard_recovery_write_acks_update")
        conn.execute(
            "CREATE TRIGGER recovery_guard_recovery_write_acks_update "
            "BEFORE UPDATE ON recovery_write_acks BEGIN SELECT 1 /*"
            + "x" * (20 * 1024)
            + "*/; END"
        )
    before = _catalog_rows(path)
    source = _source_row(path, scope.session_id)
    with pytest.raises(
        RecoveryRefused, match="protected_session_authority_unavailable"
    ):
        SessionDB(path)
    assert _catalog_rows(path) == before
    assert _source_row(path, scope.session_id) == source


def test_active_finalizer_refuses_stale_guard_before_seal_writes(
    tmp_path: Path, monkeypatch
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        _make_old_update_body(db.db_path)
        with pytest.raises(
            RecoveryRefused, match="protected_session_authority_unavailable"
        ):
            finalize(store, scope, request, evidence)
        assert (
            db._read_one(
                "SELECT phase FROM recovery_sessions WHERE session_id=?",
                (scope.session_id,),
            )[0]
            == "closing"
        )
        assert db._read_one("SELECT count(*) FROM recovery_seal_documents")[0] == 0
        assert db._read_one("SELECT count(*) FROM recovery_sealed_pages")[0] == 0
    finally:
        db.close()


def test_same_version_sealed_bytes_read_after_restart(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        assert finalize(store, scope, request, evidence).state == "sealed"
        receipt = read_seal_bytes(store, scope, "root")
        page = read_sealed_page_bytes(store, scope, "root", 0)
    finally:
        db.close()
    reopened = RecoveryStore(SessionDB(tmp_path / "state.db"))
    try:
        assert read_seal_bytes(reopened, scope, "root") == receipt
        assert read_sealed_page_bytes(reopened, scope, "root", 0) == page
    finally:
        reopened.db.close()
