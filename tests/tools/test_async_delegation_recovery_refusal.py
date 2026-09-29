"""Raw async delegation refuses protected stores before schema or worker effects."""

from __future__ import annotations

import sqlite3
import threading
import queue

import pytest

from hermes_state_recovery import RecoveryRefused
from tools import async_delegation as ad
from tests.agent.test_recovery_runtime import _admitted


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


def test_ordinary_delegation_uses_existing_schema_in_mixed_store(tmp_path, monkeypatch):
    db, _store, _scope, _registry = _admitted(tmp_path)
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    ad._reset_for_tests()
    gate = threading.Event()
    started = threading.Event()

    def runner():
        started.set()
        assert gate.wait(10)
        return {"status": "completed"}

    try:
        handle = ad.dispatch_async_delegation(
            goal="ordinary", context=None, toolsets=None, role="worker", model=None,
            session_key="key", parent_session_id="ordinary", runner=runner)
        assert handle["status"] == "dispatched"
        assert started.wait(10)
        assert ad.active_count() == 1
    finally:
        gate.set()
        if ad._executor is not None:
            ad._executor.shutdown(wait=True)
        db.close()
        ad._reset_for_tests()


def test_batch_id_collision_preserves_historical_protected_origin(
    tmp_path, monkeypatch,
):
    db, _store, scope, _registry = _admitted(tmp_path)
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    monkeypatch.setattr(ad, "_get_executor", lambda *_: pytest.fail("worker pool started"))
    ad._reset_for_tests()
    try:
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "INSERT INTO async_delegations "
                "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                "state, dispatched_at, updated_at, delivery_state, delivery_attempts, task_json) "
                "VALUES ('deleg_existing', 'key', ?, '', 'completed', 1, 1, 'pending', 0, 'historic')",
                (scope.session_id,),
            )
        result = ad.dispatch_async_delegation_batch(
            delegation_id="deleg_existing", goals=["ordinary work"], context=None,
            toolsets=None, role="worker", model=None, session_key="key",
            parent_session_id="ordinary-parent",
            runner=lambda: pytest.fail("runner started"),
        )
        assert result["status"] == "rejected"
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT parent_session_id, task_json FROM async_delegations "
                "WHERE delegation_id='deleg_existing'"
            ).fetchone() == (scope.session_id, "historic")
    finally:
        db.close()
        ad._reset_for_tests()


def test_failed_submit_never_deletes_replaced_ledger_row(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    ad._reset_for_tests()

    class ReplacingExecutor:
        def submit(self, _worker):
            with sqlite3.connect(db.db_path) as raw:
                raw.execute(
                    "UPDATE async_delegations SET parent_session_id='other-origin', "
                    "task_json='other-record' WHERE delegation_id='deleg_replaced'"
                )
            raise RuntimeError("submit failed after replacement")

    monkeypatch.setattr(ad, "_get_executor", lambda *_: ReplacingExecutor())
    try:
        result = ad.dispatch_async_delegation_batch(
            delegation_id="deleg_replaced", goals=["ordinary work"], context=None,
            toolsets=None, role="worker", model=None, session_key="key",
            parent_session_id="ordinary-parent",
            runner=lambda: pytest.fail("runner started"),
        )
        assert result["status"] == "unknown"
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT parent_session_id, task_json FROM async_delegations "
                "WHERE delegation_id='deleg_replaced'"
            ).fetchone() == ("other-origin", "other-record")
    finally:
        db.close()
        ad._reset_for_tests()


def test_failed_submit_cleans_only_its_unchanged_row(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    ad._reset_for_tests()

    class FailingExecutor:
        def submit(self, _worker):
            raise RuntimeError("submit failed")

    monkeypatch.setattr(ad, "_get_executor", lambda *_: FailingExecutor())
    try:
        result = ad.dispatch_async_delegation_batch(
            delegation_id="deleg_new", goals=["ordinary work"], context=None,
            toolsets=None, role="worker", model=None, session_key="key",
            parent_session_id="ordinary-parent",
            runner=lambda: pytest.fail("runner started"),
        )
        assert result["status"] == "rejected"
        assert result["code"] == "scheduling_failed"
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM async_delegations WHERE delegation_id='deleg_new'"
            ).fetchone() is None
    finally:
        db.close()
        ad._reset_for_tests()


def test_failed_submit_origin_change_between_check_and_delete_survives(
    tmp_path, monkeypatch,
):
    from contextlib import contextmanager
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    ad._reset_for_tests()
    before_delete = threading.Event()
    changed = threading.Event()
    errors = []

    def change_from_other_connection():
        try:
            assert before_delete.wait(10)
            with sqlite3.connect(db.db_path) as other:
                other.execute(
                    "UPDATE async_delegations SET parent_session_id='changed-origin' "
                    "WHERE delegation_id='deleg_interleaved'"
                )
        except BaseException as exc:
            errors.append(exc)
        finally:
            changed.set()

    worker = threading.Thread(target=change_from_other_connection)
    worker.start()
    original_transaction = ad._transaction

    @contextmanager
    def interleaving_transaction():
        with original_transaction() as conn:
            class ConnectionProxy:
                def execute(self, sql, params=()):
                    if sql.startswith("DELETE FROM async_delegations WHERE delegation_id=?") \
                            and "AND task_json=?" in sql:
                        before_delete.set()
                        assert changed.wait(10)
                        assert not errors
                    return conn.execute(sql, params)

            yield ConnectionProxy()

    monkeypatch.setattr(ad, "_transaction", interleaving_transaction)

    class FailingExecutor:
        def submit(self, _worker):
            raise RuntimeError("submit failed")

    monkeypatch.setattr(ad, "_get_executor", lambda *_: FailingExecutor())
    try:
        result = ad.dispatch_async_delegation_batch(
            delegation_id="deleg_interleaved", goals=["ordinary work"], context=None,
            toolsets=None, role="worker", model=None, session_key="key",
            parent_session_id="ordinary-parent",
            runner=lambda: pytest.fail("runner started"),
        )
        assert result["status"] == "unknown"
        assert not errors
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT parent_session_id FROM async_delegations "
                "WHERE delegation_id='deleg_interleaved'"
            ).fetchone() == ("changed-origin",)
    finally:
        before_delete.set()
        worker.join(timeout=10)
        db.close()
        ad._reset_for_tests()


@pytest.mark.parametrize("parent_id,expected_kind", [
    ("ordinary-parent", "ordinary_session"), (None, "unscoped_ordinary"),
])
def test_dispatch_commits_claim_before_ledger_or_worker(
    tmp_path, monkeypatch, parent_id, expected_kind,
):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    monkeypatch.setattr(ad, "_get_executor", lambda *_: pytest.fail("worker pool started"))
    ad._reset_for_tests()

    def inspect_claim(_record):
        with sqlite3.connect(db.db_path) as conn:
            assert conn.execute(
                "SELECT 1 FROM recovery_exclusions WHERE kind=? "
                "AND (session_id=? OR (session_id IS NULL AND ? IS NULL))",
                (expected_kind, parent_id, parent_id),
            ).fetchone() == (1,)
        raise RecoveryRefused("test_stop_after_claim")

    monkeypatch.setattr(ad, "_persist_dispatch", inspect_claim)
    try:
        handle = ad.dispatch_async_delegation(
            goal="ordinary", context=None, toolsets=None, role="worker", model=None,
            session_key="routing-key", parent_session_id=parent_id,
            runner=lambda: pytest.fail("runner started"))
        assert handle["status"] == "rejected"
        assert ad.active_count() == 0
    finally:
        db.close()
        ad._reset_for_tests()


def test_restart_delivery_claims_persisted_origin_before_ack(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    try:
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "INSERT INTO async_delegations "
                "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                "state, dispatched_at, updated_at, delivery_state, delivery_attempts) "
                "VALUES ('historic', 'key', 'ordinary-parent', '', 'completed', 1, 1, 'pending', 0)"
            )
        assert ad.mark_completion_delivered("historic")
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions WHERE kind='ordinary_session' "
                "AND session_id='ordinary-parent'"
            ).fetchone() == (1,)
    finally:
        db.close()


def test_retention_claims_historical_origin_before_delete(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    try:
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "INSERT INTO async_delegations "
                "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                "state, dispatched_at, updated_at, delivery_state, delivery_attempts) "
                "VALUES ('expired', 'key', 'old-parent', '', 'completed', 1, 1, 'delivered', 0)"
            )
        ad._prune_durable_records()
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions WHERE kind='ordinary_session' "
                "AND session_id='old-parent'"
            ).fetchone() == (1,)
            assert raw.execute(
                "SELECT 1 FROM async_delegations WHERE delegation_id='expired'"
            ).fetchone() is None
    finally:
        db.close()


def test_restart_replay_claims_origin_before_enqueue(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    try:
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "INSERT INTO async_delegations "
                "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                "state, dispatched_at, completed_at, updated_at, event_json, "
                "delivery_state, delivery_attempts) "
                "VALUES ('historic-replay', 'key', 'ordinary-parent', '', "
                "'completed', ?, ?, ?, '{\"type\":\"async_delegation\"}', 'pending', 0)",
                (ad.time.time(), ad.time.time(), ad.time.time()),
            )

        class CheckedQueue(queue.Queue):
            def put(self, item, *args, **kwargs):
                with sqlite3.connect(db.db_path) as raw:
                    assert raw.execute(
                        "SELECT 1 FROM recovery_exclusions WHERE kind='ordinary_session' "
                        "AND session_id='ordinary-parent'"
                    ).fetchone() == (1,)
                return super().put(item, *args, **kwargs)

        events = CheckedQueue()
        assert ad.restore_undelivered_completions(events) == 1
        assert events.get_nowait()["restored"] is True
    finally:
        db.close()


def test_delivery_refuses_origin_changed_after_claim_before_update(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    try:
        with sqlite3.connect(db.db_path) as raw:
            raw.execute(
                "INSERT INTO async_delegations "
                "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                "state, dispatched_at, updated_at, delivery_state, delivery_attempts) "
                "VALUES ('changing', 'key', 'claimed-parent', '', 'completed', 1, 1, 'pending', 0)"
            )
        original_claim = ad._claim_durable_identity

        def change_origin_after_claim(delegation_id):
            expected = original_claim(delegation_id)
            with sqlite3.connect(db.db_path) as raw:
                raw.execute(
                    "UPDATE async_delegations SET parent_session_id='different-parent' "
                    "WHERE delegation_id=?", (delegation_id,),
                )
            return expected

        monkeypatch.setattr(ad, "_claim_durable_identity", change_origin_after_claim)
        with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
            ad.mark_completion_delivered("changing")
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT delivery_state FROM async_delegations WHERE delegation_id='changing'"
            ).fetchone() == ("pending",)
            assert raw.execute(
                "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
            ).fetchall() == [("claimed-parent",)]
    finally:
        db.close()


def test_restart_origin_inventory_bound_refuses_without_partial_prune(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    monkeypatch.setattr(ad, "_MAX_DURABLE_ORIGIN_SCAN", 1)
    try:
        with sqlite3.connect(db.db_path) as raw:
            for index in range(2):
                raw.execute(
                    "INSERT INTO async_delegations "
                    "(delegation_id, origin_session, parent_session_id, origin_session_id, "
                    "state, dispatched_at, updated_at, delivery_state, delivery_attempts) "
                    "VALUES (?, 'key', ?, '', 'completed', 1, 1, 'delivered', 0)",
                    (f"expired-{index}", f"ordinary-{index}"),
                )
        with pytest.raises(RecoveryRefused, match="ordinary_ledger_inventory_too_large"):
            ad._prune_durable_records()
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute("SELECT COUNT(*) FROM async_delegations").fetchone() == (2,)
            assert raw.execute("SELECT COUNT(*) FROM recovery_exclusions").fetchone() == (0,)
    finally:
        db.close()


@pytest.mark.parametrize("shape", ["missing", "incompatible"])
def test_mixed_store_bad_async_schema_refuses_without_ghost(tmp_path, monkeypatch, shape):
    db, _store, _scope, _registry = _admitted(tmp_path)
    with sqlite3.connect(db.db_path) as conn:
        conn.execute("DROP TABLE async_delegations")
        if shape == "incompatible":
            conn.execute("CREATE TABLE async_delegations(delegation_id TEXT PRIMARY KEY)")
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    monkeypatch.setattr(ad, "_get_executor", lambda *_: pytest.fail("worker pool started"))
    ad._reset_for_tests()
    try:
        handle = ad.dispatch_async_delegation(
            goal="ordinary", context=None, toolsets=None, role="worker", model=None,
            session_key="key", parent_session_id="ordinary",
            runner=lambda: pytest.fail("runner started"))
        assert handle["status"] == "rejected"
        assert ad.active_count() == 0
        with sqlite3.connect(db.db_path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(async_delegations)")]
            assert columns == ([] if shape == "missing" else ["delegation_id"])
    finally:
        db.close()
        ad._reset_for_tests()


@pytest.mark.parametrize("failure,expected", [
    (RecoveryRefused("protected_session_dispatch"), "rejected"),
    (sqlite3.OperationalError("ambiguous commit"), "unknown"),
])
def test_persistence_failure_leaves_no_active_ghost(tmp_path, monkeypatch, failure, expected):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    ad._reset_for_tests()
    monkeypatch.setattr(ad, "_db_path", lambda: db.db_path)
    monkeypatch.setattr(ad, "_persist_dispatch", lambda _record: (_ for _ in ()).throw(failure))
    monkeypatch.setattr(ad, "_get_executor", lambda *_: pytest.fail("worker pool started"))
    try:
        handle = ad.dispatch_async_delegation(
            goal="ordinary", context=None, toolsets=None, role="worker", model=None,
            session_key="key", parent_session_id="ordinary",
            runner=lambda: pytest.fail("runner started"))
        assert handle["status"] == expected
        assert ad.active_count() == 0
    finally:
        db.close()
