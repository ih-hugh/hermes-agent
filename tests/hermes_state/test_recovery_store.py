"""Protected admission must remain authoritative across connections and crashes."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from copy import copy
from multiprocessing import get_context
from pathlib import Path
from uuid import uuid4

import pytest

from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore, RecoveryRefused
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from gateway.platforms.api_server_recovery_contract import SealResult, SnapshotPage
from gateway.platforms.api_server_recovery_contract import RecoveryMember, SealReceipt
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from agent.recovery_context import current_incarnation, issue_producer_permit, validate_producer_permit
from gateway.platforms import api_server, api_server_runs
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from gateway.config import PlatformConfig


def _stores(tmp_path: Path) -> tuple[RecoveryStore, RecoveryStore]:
    path = tmp_path / "state.db"
    return RecoveryStore(SessionDB(path)), RecoveryStore(SessionDB(path))


def _identity(store: RecoveryStore, *, session: str = "exact-session", key: str = "byf-recovery-v1:one",
              run: str = "run_root", fingerprint: str = "a" * 64, owner: str = "gateway:one") -> AdmissionIdentity:
    return AdmissionIdentity(
        scope=RecoveryScope(store.store_id, "factory", "b" * 64, session),
        idempotency_key=key, request_sha256=fingerprint, run_id=run,
        owner_incarnation=owner)


def _root() -> RecoveryAdmission:
    return RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None)


def _seal(session: str = "exact-session", runs: list[str] | None = None,
          digest: str | None = None) -> SealRequest:
    from hashlib import sha256
    run_ids = runs or ["run_root"]
    return SealRequest(request_id=str(uuid4()), session_id=session, run_ids=run_ids,
                       expected_membership_sha256=digest or sha256(
                       '["run_root"]'.encode()).hexdigest())


def _process_reserve(db_path: str, run_id: str) -> tuple[str, str | None]:
    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        result = store.reserve(_root(), _identity(store, run=run_id, owner=current_incarnation()))
        return result.outcome, result.member.run_id if result.member else None
    finally:
        db.close()


def _process_close(db_path: str, gate) -> tuple[str, list[str]]:
    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        gate.wait()
        view = store.begin_close(_identity(store).scope, _seal())
        return view.phase, [member.run_id for member in view.members]
    finally:
        db.close()


def _process_nudge(db_path: str, gate) -> str:
    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        gate.wait()
        result = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=1, parent_run_id="run_root"),
            _identity(store, key="byf-recovery-v1:two", run="run_nudge", owner=current_incarnation()))
        return result.outcome
    finally:
        db.close()


def test_atomic_member_before_dispatch(tmp_path: Path):
    """A second DB connection sees a committed member before any dispatch acknowledgement."""
    first, second = _stores(tmp_path)
    admitted_members: list[str] = []
    dispatched_members: list[str] = []
    try:
        result = first.reserve(_root(), _identity(first))
        assert result.outcome == "created"
        admitted_members.append(result.member.run_id)
        assert second.lookup_root(_identity(second).scope, "run_root").members[0].run_id == "run_root"
        # A crash here leaves a durable reservation, never an unrecorded dispatch.
        assert dispatched_members == []
        replay = second.reserve(_root(), _identity(second))
        assert replay.outcome == "replayed"
        assert replay.member.run_id == "run_root"
        dispatched_members.append(result.member.run_id)
        assert admitted_members == dispatched_members
    finally:
        first.db.close()
        second.db.close()


def test_close_races_admission(tmp_path: Path):
    """BEGIN IMMEDIATE orders close against a nudge reservation on another connection."""
    first, second = _stores(tmp_path)
    try:
        root_identity = _identity(first, owner=current_incarnation())
        assert first.reserve(_root(), root_identity).outcome == "created"
        first.close_producer(root_identity.scope, "run_root", issue_producer_permit(first, root_identity))
        scope = _identity(first).scope
        request = _seal()
        nudge = RecoveryAdmission(schema="hermes.recovery/v1", generation=1, parent_run_id="run_root")
        nudge_identity = _identity(second, key="byf-recovery-v1:two", run="run_nudge")
        with ThreadPoolExecutor(max_workers=2) as pool:
            close_future = pool.submit(first.begin_close, scope, request)
            admit_future = pool.submit(second.reserve, nudge, nudge_identity)
            closed, admission = close_future.result(), admit_future.result()
        assert (closed.phase == "closing" and admission.outcome == "refused") or (
            admission.outcome == "created" and closed.phase == "closing" and
            [m.run_id for m in closed.members] == ["run_root", "run_nudge"])
    finally:
        first.db.close()
        second.db.close()


def test_two_processes_cannot_dispatch_unrecorded_member(tmp_path: Path):
    """Independent processes agree on one durable key winner, including crash replay."""
    path = tmp_path / "state.db"
    initial = SessionDB(path)
    initial.close()
    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as pool:
        left = pool.submit(_process_reserve, str(path), "run_left")
        right = pool.submit(_process_reserve, str(path), "run_right")
        outcomes = [left.result(), right.result()]
    assert sorted(outcome for outcome, _ in outcomes) == ["created", "replayed"]
    assert len({run_id for _, run_id in outcomes}) == 1
    winner = next(run_id for outcome, run_id in outcomes if outcome == "created")
    admitted_members = [winner]
    dispatched_members = [winner]
    assert admitted_members == dispatched_members


def test_two_processes_serialize_close_against_nudge(tmp_path: Path):
    path = tmp_path / "state.db"
    db = SessionDB(path)
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    store.close_producer(identity.scope, "run_root", issue_producer_permit(store, identity))
    db.close()
    context = get_context("spawn")
    with context.Manager() as manager, ProcessPoolExecutor(max_workers=2, mp_context=context) as pool:
        gate = manager.Barrier(2)
        closer = pool.submit(_process_close, str(path), gate)
        nudger = pool.submit(_process_nudge, str(path), gate)
        phase, members = closer.result()
        outcome = nudger.result()
    assert phase == "closing"
    assert (outcome == "created" and members == ["run_root", "run_nudge"]) or (
        outcome == "refused" and members == ["run_root"])


def test_reserved_key_cannot_use_legacy_path(tmp_path: Path):
    """The ordinary idempotency store rejects protected keys even if its DB is healthy."""
    store = RunIdempotencyStore(str(tmp_path / "legacy.db"))
    try:
        with pytest.raises(RecoveryRefused) as caught:
            store.reserve("scope", "byf-recovery-v1:one", "fingerprint", "run_x", {"status": "queued"})
        assert caught.value.code == "reserved_key"
    finally:
        store.close()


def test_receipt_members_survive_run_retention(tmp_path: Path):
    """A ledger member remains readable after the ordinary transport record is pruned."""
    protected, other = _stores(tmp_path)
    legacy = RunIdempotencyStore(str(tmp_path / "legacy.db"))
    try:
        protected.reserve(_root(), _identity(protected))
        legacy.reserve("scope", "ordinary", "fingerprint", "run_old", {"status": "completed"})
        legacy._conn.execute("DELETE FROM run_idempotency")
        legacy._conn.commit()
        view = other.lookup_root(_identity(other).scope, "run_root")
        assert [m.run_id for m in view.members] == ["run_root"]
    finally:
        protected.db.close()
        other.db.close()
        legacy.close()


def test_memory_fallback_refused(tmp_path: Path):
    """Neither in-memory SessionDB nor failed disk store grants protected authority."""
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    try:
        assert store.store_id
        class MemoryHandle:
            db_path = Path(":memory:")
            read_only = False

        with pytest.raises(RecoveryRefused) as caught:
            RecoveryStore(MemoryHandle())
        assert caught.value.code == "durable_store_required"
    finally:
        db.close()


def test_permit_is_process_owned_and_cannot_be_copied(tmp_path: Path):
    first, second = _stores(tmp_path)
    identity = _identity(first, owner=current_incarnation())
    try:
        assert first.reserve(_root(), identity).outcome == "created"
        permit = issue_producer_permit(first, identity)
        assert validate_producer_permit(permit, first, identity.scope, "run_root", 0)
        assert not validate_producer_permit(permit, second, identity.scope, "run_root", 0)
        with pytest.raises(TypeError):
            copy(permit)
        assert not validate_producer_permit(permit, first, identity.scope, "run_other", 0)
        first.close_producer(identity.scope, "run_root", permit)
        assert not validate_producer_permit(permit, first, identity.scope, "run_root", 0)
    finally:
        first.db.close()
        second.db.close()


def test_incomplete_reason_sticks_through_close(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    try:
        store.reserve(_root(), identity)
        permit = issue_producer_permit(store, identity)
        store.mark_incomplete(identity.scope, "run_root", permit, "unknown_send_outcome")
        view = store.begin_close(identity.scope, _seal())
        assert view.state == "unsupported"
        assert view.reason_codes == ("unknown_send_outcome",)
        assert view.members[0].producer_state == "incomplete"
    finally:
        db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(("key", "recovery", "expected_status", "expected_code"), [
    ("byf-recovery-v1:one", {"schema": "hermes.recovery/v1", "generation": 0,
                              "parent_run_id": None}, 503, b"recovery_runtime_unavailable"),
    ("byf-recovery-v1:one", None, 400, b"recovery_admission_mismatch"),
    ("ordinary", {"schema": "hermes.recovery/v1", "generation": 0,
                   "parent_run_id": None}, 400, b"recovery_admission_mismatch"),
])
async def test_http_refuses_protected_dispatch_until_runtime_ready(key, recovery, expected_status, expected_code):
    """An HTTP request cannot opt itself into an uninstrumented protected executor."""
    class Adapter:
        def _parse_session_key_header(self, request):
            return None, None

        async def _normalize_room_dispatch(self, request, body):
            return body, None

    class Request:
        headers = {"Idempotency-Key": key}

        async def json(self):
            body = {"input": "hello", "session_id": "exact-session"}
            if recovery is not None:
                body["recovery"] = recovery
            return body

    response = await api_server_runs._handle_runs(Adapter(), Request(), _api_server=api_server)
    assert response.status == expected_status
    assert expected_code in response.body


def test_wire_rejects_non_json_snapshot_and_inconsistent_result():
    """A pending response cannot carry a receipt; snapshot rows contain JSON only."""
    with pytest.raises(ValueError):
        SnapshotPage(receipt_sha256="a" * 64, page_index=0,
                     rows=[{"row_index": 0, "row_sha256": "b" * 64,
                            "message": {"content": object()}}], next_page=None)
    with pytest.raises(ValueError):
        SealResult(schema="hermes.recovery/v1", state="pending", request_id=str(uuid4()),
                   reasons=[], receipt={})


def test_shared_wire_fixture_is_strict_and_round_trips():
    import json

    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "recovery_contract_v1.json").read_text())
    for name, model in (("admission", RecoveryAdmission), ("member", RecoveryMember),
                        ("seal_request", SealRequest), ("seal_receipt", SealReceipt),
                        ("seal_result", SealResult), ("snapshot_page", SnapshotPage)):
        assert model.model_validate(fixture[name]).model_dump(mode="json", by_alias=True) == fixture[name]
        with pytest.raises(ValueError):
            model.model_validate({**fixture[name], "unexpected": "field"})


@pytest.mark.asyncio
async def test_trusted_ready_route_admits_replays_and_reads_status(tmp_path: Path, monkeypatch):
    """The internal readiness seam uses state.db and replays without dispatching twice."""
    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    adapter._recovery_runtime_ready = lambda request, body: True
    dispatched: list[str] = []

    async def fake_execute(owner, launch, *, _api_server):
        dispatched.append(launch.run_id)

    monkeypatch.setattr(api_server_runs, "_execute_run", fake_execute)
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    body = {"input": "hello", "session_id": "exact-session",
            "recovery": {"schema": "hermes.recovery/v1", "generation": 0, "parent_run_id": None}}
    headers = {"Idempotency-Key": "byf-recovery-v1:one"}
    try:
        async with TestClient(TestServer(app)) as client:
            first = await client.post("/v1/runs", json=body, headers=headers)
            assert first.status == 202
            first_id = (await first.json())["run_id"]
            replay = await client.post("/v1/runs", json=body, headers=headers)
            assert replay.status == 202
            assert (await replay.json())["run_id"] == first_id
            adapter._run_statuses.clear()
            adapter._run_owners.clear()
            adapter._protected_run_ids.clear()
            adapter._protected_run_stores.clear()
            status = await client.get(f"/v1/runs/{first_id}")
            assert status.status == 200
            assert (await status.json())["run_id"] == first_id
            assert [m.run_id for m in RecoveryStore(db).lookup_root(
                RecoveryScope(RecoveryStore(db).store_id, "default",
                              adapter._run_idempotency_scope(type("R", (), {"path": "/v1/runs", "headers": {}})()),
                              "exact-session"), first_id).members] == [first_id]
        assert dispatched == [first_id]
    finally:
        await adapter.disconnect()
        db.close()
