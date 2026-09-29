"""Durable exclusion claims serialize ordinary effects with protected roots."""

from __future__ import annotations

import sqlite3
import threading
from multiprocessing import get_context
from pathlib import Path
from uuid import uuid4

import pytest

from agent.recovery_context import (
    bind_write_permit, current_incarnation, issue_producer_permit, issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry, bind_registry
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore
from hermes_state_recovery_exclusions import (
    authorize_or_claim_agent_construction, begin_raw_schema_claim,
    claim_ordinary_sessions, claim_unscoped_ordinary,
    existing_protected_store, finish_raw_schema_claim,
)
from tests.recovery_provider_fixture import provider_admission


def _hold_sqlite_connection(path: str, ready, release) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("SELECT 1 FROM sqlite_master").fetchone()
        ready.set()
        assert release.wait(10)


def _reserve(store: RecoveryStore, sid: str, run_id: str):
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, sid)
    return store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:" + run_id, "a" * 64, run_id,
                          current_incarnation(), provider_admission(sid)))


def test_absent_store_bootstrap_exact_claim_and_reuse(tmp_path: Path):
    path = tmp_path / "state.db"
    sid = "generated-" + uuid4().hex
    assert not path.exists()
    first = claim_ordinary_sessions(path, (sid,))
    assert first.session_ids == (sid,)
    with sqlite3.connect(path) as raw:
        assert raw.execute("SELECT kind,session_id FROM recovery_exclusions").fetchall() == [
            ("ordinary_session", sid)]
        assert raw.execute("SELECT COUNT(*) FROM sqlite_master WHERE name GLOB 'recovery_*'").fetchone()[0] == 4
    db = SessionDB(path)
    try:
        store = RecoveryStore(db)
        assert _reserve(store, sid, "root").reason == "ordinary_session_claimed"
        assert claim_ordinary_sessions(path, (sid,)).session_ids == (sid,)
        assert claim_ordinary_sessions(path, ("another",)).session_ids == ("another",)
        assert _reserve(store, "protected-other", "other-root").outcome == "created"
    finally:
        db.close()


@pytest.mark.parametrize("content", [b"", bytes(4096), b"not sqlite"])
def test_preexisting_unclassifiable_store_is_unchanged(tmp_path: Path, content: bytes):
    path = tmp_path / "state.db"
    path.write_bytes(content)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        begin_raw_schema_claim(path)
    assert path.read_bytes() == content
    assert not list(tmp_path.glob("state.db.*.bak"))


def test_valid_empty_sqlite_header_can_bootstrap(tmp_path: Path):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as raw:
        raw.execute("PRAGMA user_version=1")
    assert path.read_bytes().startswith(b"SQLite format 3\x00")
    assert claim_ordinary_sessions(path, ("ordinary",)).session_ids == ("ordinary",)


def test_bootstrap_refuses_path_replaced_after_exclusive_creation(tmp_path: Path,
                                                                  monkeypatch):
    import hermes_state as hs

    path = tmp_path / "state.db"
    original = hs._secure_state_db_files

    def swap(target, *, create_main=False):
        original(target, create_main=create_main)
        target.unlink()
        target.write_bytes(b"")

    monkeypatch.setattr(hs, "_secure_state_db_files", swap)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        begin_raw_schema_claim(path)
    assert path.read_bytes() == b""


def test_raw_claim_close_cannot_retire_wal_during_initializer_open(tmp_path: Path,
                                                                    monkeypatch):
    """An in-process raw close must not expose a pre-guard WAL to a peer close."""
    import hermes_state as hs
    from hermes_state_dbfile import iter_deleted_sqlite_sidecar_holders

    path = tmp_path / "state.db"
    initial = SessionDB(path)
    initial.close()
    entered, resume = threading.Event(), threading.Event()
    original_hold = hs._lockguard.hold
    opened: list[SessionDB] = []
    errors: list[BaseException] = []

    def paused_hold(db_path, held=None):
        if threading.current_thread().name == "initializer":
            entered.set()
            assert resume.wait(10)
        return original_hold(db_path, held)

    def open_initializer():
        try:
            opened.append(SessionDB(path))
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(hs._lockguard, "hold", paused_hold)
    initializer = threading.Thread(target=open_initializer, name="initializer")
    initializer.start()
    context = get_context("spawn")
    ready, release = context.Event(), context.Event()
    peer = context.Process(target=_hold_sqlite_connection, args=(str(path), ready, release))
    try:
        assert entered.wait(10)
        peer.start()
        assert ready.wait(10)
        raw = begin_raw_schema_claim(path)
        assert raw is not None
        release.set()
        peer.join(10)
        assert peer.exitcode == 0
        assert iter_deleted_sqlite_sidecar_holders(path) == []
    finally:
        release.set()
        resume.set()
        initializer.join(10)
        if peer.pid is not None and peer.is_alive():
            peer.terminate()
            peer.join(10)
        for db in opened:
            db.close()
    assert not errors


def test_root_first_refuses_exact_and_unscoped_but_other_ordinary_works(tmp_path: Path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    try:
        store = RecoveryStore(db)
        assert _reserve(store, "protected", "root").outcome == "created"
        assert existing_protected_store(path)
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            claim_ordinary_sessions(path, ("protected",))
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            claim_unscoped_ordinary(path)
        assert claim_ordinary_sessions(path, ("other",)).session_ids == ("other",)
        assert claim_ordinary_sessions(path, ("other",)).session_ids == ("other",)
    finally:
        db.close()


def test_unscoped_is_permanent_and_preserves_ordinary_work(tmp_path: Path):
    path = tmp_path / "state.db"
    claim_unscoped_ordinary(path)
    claim_unscoped_ordinary(path)
    db = SessionDB(path)
    try:
        store = RecoveryStore(db)
        assert _reserve(store, "future", "root").reason == "unscoped_ordinary_claimed"
        assert claim_ordinary_sessions(path, ("ordinary",)).session_ids == ("ordinary",)
    finally:
        db.close()


def test_two_raw_claims_have_independent_release_and_crash_sticks(tmp_path: Path):
    path = tmp_path / "state.db"
    first = begin_raw_schema_claim(path)
    second = begin_raw_schema_claim(path)
    db = SessionDB(path)
    try:
        store = RecoveryStore(db)
        assert _reserve(store, "protected", "root").reason == "raw_schema_active"
        finish_raw_schema_claim(first)
        assert _reserve(store, "protected", "root").reason == "raw_schema_active"
        finish_raw_schema_claim(second)
        assert _reserve(store, "protected", "root").outcome == "created"
        with pytest.raises(RecoveryRefused, match="invalid_raw_schema_lease"):
            finish_raw_schema_claim(first)
    finally:
        db.close()

    crash_path = tmp_path / "crash.db"
    lost = begin_raw_schema_claim(crash_path)
    assert lost is not None
    crash_db = SessionDB(crash_path)
    try:
        assert _reserve(RecoveryStore(crash_db), "future", "future-root").reason == "raw_schema_active"
    finally:
        crash_db.close()


def test_raw_lease_cannot_release_through_another_store_connection(tmp_path: Path):
    first_path, other_path = tmp_path / "first.db", tmp_path / "other.db"
    first, other = begin_raw_schema_claim(first_path), begin_raw_schema_claim(other_path)
    with sqlite3.connect(other_path) as wrong:
        with pytest.raises(RecoveryRefused, match="invalid_raw_schema_lease"):
            finish_raw_schema_claim(first, conn=wrong)
    for path in (first_path, other_path):
        with sqlite3.connect(path) as raw:
            assert raw.execute(
                "SELECT count(*) FROM recovery_exclusions WHERE kind='raw_schema'").fetchone()[0] == 1
    finish_raw_schema_claim(first)
    finish_raw_schema_claim(other)


@pytest.mark.parametrize("winner", ["ordinary", "protected"])
def test_real_file_orderings_hold_effect_sentinel(tmp_path: Path, winner: str):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    store = RecoveryStore(db)
    ordinary_go, root_go = threading.Event(), threading.Event()
    ordinary_done, root_done = threading.Event(), threading.Event()
    effects: list[str] = []
    outcomes: dict[str, str] = {}

    def ordinary():
        assert ordinary_go.wait(3)
        try:
            claim_ordinary_sessions(path, ("race",))
            effects.append("ordinary")
            outcomes["ordinary"] = "claimed"
        except RecoveryRefused as exc:
            outcomes["ordinary"] = exc.code
        finally:
            ordinary_done.set()

    def protected():
        assert root_go.wait(3)
        outcomes["protected"] = _reserve(store, "race", "root").outcome
        root_done.set()

    threads = [threading.Thread(target=ordinary), threading.Thread(target=protected)]
    for thread in threads:
        thread.start()
    try:
        if winner == "ordinary":
            ordinary_go.set()
            assert ordinary_done.wait(3)
            root_go.set()
        else:
            root_go.set()
            assert root_done.wait(3)
            ordinary_go.set()
        for thread in threads:
            thread.join(3)
        assert not any(thread.is_alive() for thread in threads)
        if winner == "ordinary":
            assert outcomes == {"ordinary": "claimed", "protected": "refused"}
            assert effects == ["ordinary"]
        else:
            assert outcomes == {"protected": "created", "ordinary": "protected_session_dispatch"}
            assert effects == []
    finally:
        ordinary_go.set()
        root_go.set()
        for thread in threads:
            thread.join(3)
        db.close()


def test_corrupt_exclusion_shape_is_never_absence(tmp_path: Path):
    path = tmp_path / "state.db"
    claim_ordinary_sessions(path, ("ordinary",))
    with sqlite3.connect(path) as raw:
        raw.execute("DROP TRIGGER recovery_guard_recovery_exclusions_delete")
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        claim_ordinary_sessions(path, ("other",))
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        existing_protected_store(path)


def test_sessiondb_holds_unique_raw_claim_before_schema_and_releases_on_success(tmp_path: Path,
                                                                                monkeypatch):
    path = tmp_path / "state.db"
    entered: list[tuple[str, ...]] = []
    original = SessionDB._init_schema

    def observed(self):
        rows = self._conn.execute(
            "SELECT claim_id FROM recovery_exclusions WHERE kind='raw_schema'").fetchall()
        entered.append(tuple(row[0] for row in rows))
        assert len(rows) == 1
        return original(self)

    monkeypatch.setattr(SessionDB, "_init_schema", observed)
    db = SessionDB(path)
    try:
        assert len(entered) == 1
        assert db._read_one("SELECT 1 FROM recovery_exclusions WHERE kind='raw_schema'") is None
    finally:
        db.close()


def test_sessiondb_schema_failure_keeps_raw_claim(tmp_path: Path, monkeypatch):
    path = tmp_path / "state.db"

    def fail_after_claim(self):
        assert self._conn.execute(
            "SELECT 1 FROM recovery_exclusions WHERE kind='raw_schema'").fetchone()
        raise RuntimeError("scratch schema failure")

    monkeypatch.setattr(SessionDB, "_init_schema", fail_after_claim)
    with pytest.raises(RuntimeError, match="scratch schema failure"):
        SessionDB(path)
    with sqlite3.connect(path) as raw:
        assert raw.execute(
            "SELECT count(*) FROM recovery_exclusions WHERE kind='raw_schema'").fetchone()[0] == 1


def test_sessiondb_existing_protected_branch_skips_schema_reconciliation(tmp_path: Path,
                                                                          monkeypatch):
    path = tmp_path / "state.db"
    first = SessionDB(path)
    try:
        assert _reserve(RecoveryStore(first), "protected", "root").outcome == "created"
    finally:
        first.close()

    def prohibited(self):
        raise AssertionError("protected existing-schema branch ran DDL")

    monkeypatch.setattr(SessionDB, "_init_schema", prohibited)
    second = SessionDB(path)
    try:
        assert second._read_one("SELECT session_id FROM recovery_sessions")[0] == "protected"
        assert claim_ordinary_sessions(path, ("other",)).session_ids == ("other",)
    finally:
        second.close()


def test_simultaneous_schema_openers_release_only_their_own_claim(tmp_path: Path,
                                                                  monkeypatch):
    path = tmp_path / "state.db"
    first_entered, first_release, second_done = (
        threading.Event(), threading.Event(), threading.Event())
    original = SessionDB._init_schema
    opened: dict[str, SessionDB] = {}
    failures: list[BaseException] = []

    def held(self):
        if threading.current_thread().name == "first-opener":
            first_entered.set()
            assert first_release.wait(5)
        return original(self)

    def open_named(name: str):
        try:
            opened[name] = SessionDB(path)
        except BaseException as exc:
            failures.append(exc)
        finally:
            if name == "second":
                second_done.set()

    monkeypatch.setattr(SessionDB, "_init_schema", held)
    first = threading.Thread(target=open_named, args=("first",), name="first-opener")
    second = threading.Thread(target=open_named, args=("second",), name="second-opener")
    first.start()
    try:
        assert first_entered.wait(5)
        second.start()
        assert second_done.wait(5)
        assert not failures
        with sqlite3.connect(path) as raw:
            rows = raw.execute(
                "SELECT claim_id FROM recovery_exclusions WHERE kind='raw_schema'").fetchall()
            assert len(rows) == 1
        assert _reserve(RecoveryStore(opened["second"]), "blocked", "root").reason == "raw_schema_active"
        first_release.set()
        first.join(5)
        assert not failures
        assert _reserve(RecoveryStore(opened["second"]), "accepted", "other").outcome == "created"
    finally:
        first_release.set()
        first.join(5)
        if second.ident is not None:
            second.join(5)
        for db in opened.values():
            db.close()


def test_direct_construction_facade_requires_exact_active_protected_authority(tmp_path: Path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    store = RecoveryStore(db)
    try:
        admitted = _reserve(store, "protected", "root")
        assert admitted.outcome == "created"
        scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected")
        registry = ProducerRegistry(
            store, scope, "root", 0, issue_producer_permit(store, admitted.handoff))
        writer = issue_write_permit(registry.permit, store, scope, "root", 0)
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            authorize_or_claim_agent_construction("protected", path, db, None, None, None)
        with bind_registry(registry), bind_write_permit(writer):
            with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
                authorize_or_claim_agent_construction("protected", path, db, registry, None, writer)
            lease = registry.enter(registry.permit, "executor")
            lease.run(lambda: authorize_or_claim_agent_construction(
                "protected", path, db, registry, lease, writer))
            with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
                authorize_or_claim_agent_construction("protected", path, db, None, None, writer)
        authorize_or_claim_agent_construction("ordinary", path, db, None, None, None)
        assert _reserve(store, "ordinary", "other").reason == "ordinary_session_claimed"
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            authorize_or_claim_agent_construction("protected", path, None, None, None, None)
        with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
            authorize_or_claim_agent_construction("ordinary2", tmp_path / "other.db", db,
                                                  None, None, None)
    finally:
        db.close()
