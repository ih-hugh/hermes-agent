"""Ordinary dispatch claims exact session identities before effects."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
)
from hermes_state_recovery_exclusions import claim_ordinary_sessions
from hermes_recovery_dispatch import claim_exact_ordinary, selected_state_db_path
from tests.recovery_provider_fixture import provider_admission


def test_absent_and_exact_bootstrap_reuse_claim_before_dispatch(tmp_path: Path):
    path = tmp_path / "state.db"
    first = claim_exact_ordinary(path, ("generated",))
    assert first.original_ids == first.resolved_ids == ("generated",)
    assert claim_exact_ordinary(path, ("generated",)).resolved_ids == ("generated",)
    with sqlite3.connect(path) as raw:
        assert raw.execute(
            "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
        ).fetchall() == [("generated",)]


def test_partial_ordinary_catalog_does_not_become_bootstrap(tmp_path: Path):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as raw:
        raw.execute("CREATE TABLE sessions(id TEXT)")
    claim_ordinary_sessions(path, ("existing",))
    with pytest.raises(
        RecoveryRefused, match="protected_session_authority_unavailable"
    ):
        claim_exact_ordinary(path, ("new",))
    with sqlite3.connect(path) as raw:
        assert raw.execute(
            "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
        ).fetchall() == [("existing",)]


def test_parent_and_compression_tip_are_one_exact_claim(tmp_path: Path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    try:
        db.create_session("parent", source="webui")
        db.append_message("parent", "user", "original")
        assert db.try_acquire_compression_lock("parent", "winner", ttl_seconds=60)
        db.publish_compression_child(
            parent_session_id="parent",
            child_session_id="child",
            source="webui",
            messages=[{"role": "user", "content": "summary"}],
            compression_lock_holder="winner",
        )
        claim = claim_exact_ordinary(path, ("parent",))
        assert claim.original_ids == ("parent",)
        assert claim.resolved_ids == ("child",)
        with sqlite3.connect(path) as raw:
            assert set(
                raw.execute(
                    "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
                ).fetchall()
            ) == {("parent",), ("child",)}
    finally:
        db.close()


def test_protected_tip_refuses_without_partial_parent_claim(
    tmp_path: Path, monkeypatch
):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    try:
        store = RecoveryStore(db)
        scope = RecoveryScope(store.store_id, "factory", "b" * 64, "child")
        admitted = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=0, parent_run_id=None
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:child",
                "a" * 64,
                "root",
                "gateway:one",
                provider_admission("child"),
            ),
        )
        assert admitted.outcome == "created", admitted.reason
        # Force a tip returned after the read boundary to pin the atomic claim
        # transaction even when the resolver's own protected check is bypassed.
        import hermes_recovery_refusal

        monkeypatch.setattr(
            hermes_recovery_refusal,
            "readonly_resume_session",
            lambda sid, *, db_path: "child" if sid == "parent" else sid,
        )
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            claim_exact_ordinary(path, ("parent",))
        with sqlite3.connect(path) as raw:
            assert (
                raw.execute(
                    "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
                ).fetchall()
                == []
            )
    finally:
        db.close()


def test_selected_database_path_never_falls_back_from_invalid_selected_object(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: tmp_path)
    assert selected_state_db_path(None) == tmp_path / "state.db"
    db = SessionDB(tmp_path / "selected.db")
    try:
        assert selected_state_db_path(db) == db.db_path
    finally:
        db.close()
    with pytest.raises(
        RecoveryRefused, match="protected_session_authority_unavailable"
    ):
        selected_state_db_path(object())
