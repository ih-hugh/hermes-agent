"""Protected admission must remain authoritative across connections and crashes."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from copy import copy, deepcopy
from multiprocessing import get_context
from pathlib import Path
from types import SimpleNamespace
import asyncio
import json
import sqlite3
import threading
from uuid import uuid4

import pytest

from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore, RecoveryRefused
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from gateway.platforms.api_server_recovery_contract import (
    ArtifactRow, ManifestArtifactPage, SealResult,
)
from gateway.platforms.api_server_recovery_artifacts import document_sha256
from gateway.platforms.api_server_recovery_contract import RecoveryMember, SealReceipt
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from agent.recovery_context import (
    current_incarnation, issue_producer_permit, issue_write_permit,
    validate_producer_permit, validate_write_permit,
)
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
        assert second.lookup_key(_identity(second).scope, "byf-recovery-v1:one", "a" * 64).member.run_id == "run_root"
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
        admitted = first.reserve(_root(), root_identity)
        assert admitted.outcome == "created"
        first.close_producer(root_identity.scope, "run_root", issue_producer_permit(first, admitted.handoff))
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
    result = store.reserve(_root(), identity)
    store.close_producer(identity.scope, "run_root", issue_producer_permit(store, result.handoff))
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
        protected.begin_close(_identity(protected).scope, _seal())
        legacy.reserve("scope", "ordinary", "fingerprint", "run_old", {"status": "completed"})
        legacy._conn.execute("DELETE FROM run_idempotency")
        legacy._conn.commit()
        view = other.lookup_root(_identity(other).scope, "run_root")
        assert [m.run_id for m in view.members] == ["run_root"]
    finally:
        protected.db.close()
        other.db.close()
        legacy.close()


def test_lookup_root_requires_recorded_close(tmp_path: Path):
    first, second = _stores(tmp_path)
    try:
        first.reserve(_root(), _identity(first))
        with pytest.raises(RecoveryRefused) as absent:
            second.lookup_root(_identity(second).scope, "run_root")
        assert absent.value.code == "not_found"
        first.begin_close(_identity(first).scope, _seal())
        assert second.lookup_root(_identity(second).scope, "run_root").request_id is not None
    finally:
        first.db.close()
        second.db.close()


def test_readback_keeps_revision_and_members_in_one_snapshot(tmp_path: Path, monkeypatch):
    first, second = _stores(tmp_path)
    identity = _identity(first, owner=current_incarnation())
    try:
        admitted = first.reserve(_root(), identity)
        permit = issue_producer_permit(first, admitted.handoff)
        first.begin_close(identity.scope, _seal())
        original_view = RecoveryStore._view
        changed = False

        def change_between_reads(cls, conn, row):
            nonlocal changed
            if not changed:
                changed = True
                first.close_producer(identity.scope, "run_root", permit)
            return original_view(conn, row)

        monkeypatch.setattr(RecoveryStore, "_view", classmethod(change_between_reads))
        view = second.lookup_root(_identity(second).scope, "run_root")
        assert view.revision == 2
        assert view.members[0].producer_state == "open"
    finally:
        first.db.close()
        second.db.close()


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
        admitted = first.reserve(_root(), identity)
        assert admitted.outcome == "created"
        permit = issue_producer_permit(first, admitted.handoff)
        assert validate_producer_permit(permit, first, identity.scope, "run_root", 0)
        with pytest.raises(RecoveryRefused) as repeated:
            issue_producer_permit(first, admitted.handoff)
        assert repeated.value.code == "admission_handoff_consumed"
        with pytest.raises(RecoveryRefused):
            issue_producer_permit(first, identity)
        assert first.reserve(_root(), identity).handoff is None
        assert not validate_producer_permit(permit, second, identity.scope, "run_root", 0)
        with pytest.raises(TypeError):
            copy(permit)
        assert not validate_producer_permit(permit, first, identity.scope, "run_other", 0)
        write = issue_write_permit(permit, first, identity.scope, "run_root", 0)
        assert validate_write_permit(write, first, identity.scope, "run_root", 0)
        assert not validate_write_permit(permit, first, identity.scope, "run_root", 0)
        assert not validate_producer_permit(write, first, identity.scope, "run_root", 0)
        with pytest.raises(RecoveryRefused):
            first.close_producer(identity.scope, "run_root", write)
        first.close_producer(identity.scope, "run_root", permit)
        assert not validate_producer_permit(permit, first, identity.scope, "run_root", 0)
    finally:
        first.db.close()
        second.db.close()


@pytest.mark.parametrize("changed_column", ["idempotency_key", "request_sha256"])
def test_handoff_checks_complete_recorded_identity(tmp_path: Path, changed_column: str):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    try:
        admitted = store.reserve(_root(), identity)
        # Simulate a previously committed authoritative ledger change; ordinary SQL
        # cannot mutate recovery identity after admission.
        store._write(lambda conn: conn.execute(
            f"UPDATE recovery_members SET {changed_column}=? WHERE run_id=?",
            ("different" if changed_column == "idempotency_key" else "c" * 64, "run_root")))
        with pytest.raises(RecoveryRefused) as refused:
            issue_producer_permit(store, admitted.handoff)
        assert refused.value.code == "admission_handoff_mismatch"
    finally:
        db.close()


def test_incomplete_reason_sticks_through_close(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    try:
        admitted = store.reserve(_root(), identity)
        permit = issue_producer_permit(store, admitted.handoff)
        store.mark_incomplete(identity.scope, "run_root", permit, "unknown_send_outcome")
        view = store.begin_close(identity.scope, _seal())
        assert view.state == "unsupported"
        assert view.reason_codes == ("unknown_send_outcome",)
        assert view.members[0].producer_state == "incomplete"
    finally:
        db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(("key", "recovery", "expected_status", "expected_code"), [
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

        def __init__(self):
            body = {"input": "hello", "session_id": "exact-session"}
            if recovery is not None:
                body["recovery"] = recovery
            self._body = body
            self.content = self
            self._raw = json.dumps(body).encode()

        async def read(self, limit):
            chunk, self._raw = self._raw[:limit], self._raw[limit:]
            return chunk

        async def json(self):
            return self._body

    response = await api_server_runs._handle_runs(Adapter(), Request(), _api_server=api_server)
    assert response.status == expected_status
    assert expected_code in response.body


@pytest.mark.asyncio
async def test_raw_protected_body_limit_precedes_json_parse():
    class Adapter:
        def _parse_session_key_header(self, request):
            return None, None

    class Request:
        headers = {"Idempotency-Key": "byf-recovery-v1:one"}

        def __init__(self):
            self.content = self
            self.remaining = 16 * 1024 + 1
            self.reads = 0

        async def read(self, limit):
            amount = min(257, limit, self.remaining)
            self.remaining -= amount
            self.reads += 1
            return b" " * amount

        async def json(self):
            raise AssertionError("oversized protected JSON must not be parsed")

    request = Request()
    response = await api_server_runs._handle_runs(Adapter(), request, _api_server=api_server)
    assert response.status == 413
    assert b"recovery_body_too_large" in response.body
    assert request.reads > 1


def test_wire_rejects_non_json_snapshot_and_inconsistent_result():
    """A pending response cannot carry a receipt; snapshot rows contain JSON only."""
    with pytest.raises(ValueError):
        ArtifactRow(row_index=0, kind="transcript", row_sha256="b" * 64,
                    value={"content": object()})
    with pytest.raises(ValueError):
        SealResult(schema="hermes.recovery/v1", state="pending", request_id=str(uuid4()),
                   reasons=[], receipt={})


def test_shared_wire_fixture_is_strict_and_round_trips():
    import json

    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "recovery_contract_v1.json").read_text())
    for name, model in (("admission", RecoveryAdmission), ("member", RecoveryMember),
                        ("seal_request", SealRequest), ("seal_receipt", SealReceipt),
                        ("seal_result", SealResult), ("snapshot_page", ManifestArtifactPage)):
        assert model.model_validate(fixture[name]).model_dump(mode="json", by_alias=True) == fixture[name]
        with pytest.raises(ValueError):
            model.model_validate({**fixture[name], "unexpected": "field"})
    assert isinstance(SealRequest.model_validate(fixture["seal_request"]).run_ids, tuple)
    assert isinstance(SealReceipt.model_validate(fixture["seal_receipt"]).members, tuple)
    assert isinstance(ManifestArtifactPage.model_validate(fixture["snapshot_page"]).descriptors, tuple)
    assert ManifestArtifactPage.model_validate_json(json.dumps(fixture["snapshot_page"])).model_dump(
        mode="json", by_alias=True) == fixture["snapshot_page"]


def test_snapshot_row_nested_json_is_immutable_and_serializes():
    value = {"blocks": [{"text": "hello"}]}
    row = ArtifactRow(row_index=0, kind="transcript",
                      row_sha256=document_sha256("hermes.recovery.row/transcript/v1",
                                                  {"row_index": 0, "kind": "transcript", "value": value}),
                      value=value)
    with pytest.raises(TypeError):
        row.value["blocks"] = []
    assert isinstance(row.value["blocks"], tuple)
    with pytest.raises(TypeError):
        row.value["blocks"][0]["text"] = "changed"
    assert row.model_dump(mode="json")["value"] == value


@pytest.mark.parametrize(("field", "value"), [
    ("gateway_incarnation", ""), ("profile", ""), ("scope_digest", "bad"),
    ("session_id", ""), ("revision", -1), ("sealed_at", float("inf")),
])
def test_receipt_rejects_unbounded_identity_or_time(field: str, value):
    import json

    fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "recovery_contract_v1.json").read_text())
    receipt = deepcopy(fixture["seal_receipt"])
    receipt[field] = value
    with pytest.raises(ValueError):
        SealReceipt.model_validate(receipt)


def test_seal_result_rejects_unknown_or_unbounded_reason():
    with pytest.raises(ValueError):
        SealResult(schema="hermes.recovery/v1", state="unsupported", request_id=str(uuid4()),
                   reasons=["arbitrary developer exception " * 100], receipt=None)


def test_wire_rejects_unbounded_member_identity_and_revision():
    with pytest.raises(ValueError):
        RecoveryMember(run_id="x" * 256, generation=0, parent_run_id=None,
                       request_sha256="a" * 64, producer_state="open")
    with pytest.raises(ValueError):
        RecoveryMember(run_id="run_nudge", generation=1, parent_run_id="",
                       request_sha256="a" * 64, producer_state="open")
    with pytest.raises(ValueError):
        SealRequest(request_id=str(uuid4()), session_id="exact-session",
                    run_ids=["x" * 256], expected_membership_sha256="a" * 64)
    receipt = json.loads((Path(__file__).parents[1] / "fixtures" / "recovery_contract_v1.json").read_text())[
        "seal_receipt"]
    receipt["revision"] = 2**63
    with pytest.raises(ValueError):
        SealReceipt.model_validate(receipt)


@pytest.mark.asyncio
async def test_trusted_ready_route_admits_replays_and_reads_status(tmp_path: Path, monkeypatch):
    """The internal readiness seam uses state.db and replays without dispatching twice."""
    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    dispatched: list[str] = []

    async def fake_execute(owner, launch, *, _api_server):
        assert launch.recovery_handoff is not None
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
            unavailable = await client.post("/v1/runs", json=body, headers=headers)
            assert unavailable.status == 503
            adapter._recovery_runtime_ready = lambda request, body: True
            first = await client.post("/v1/runs", json=body, headers=headers)
            assert first.status == 202
            first_id = (await first.json())["run_id"]
            adapter._recovery_runtime_ready = lambda request, body: False
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
            scope = RecoveryScope(RecoveryStore(db).store_id, "default",
                                  adapter._run_idempotency_scope(type("R", (), {
                                      "path": "/v1/runs", "headers": {}})()), "exact-session")
            assert RecoveryStore(db).owns_run(scope.profile, scope.scope_digest, first_id)
        assert dispatched == [first_id]
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_writer_lock_does_not_block_unrelated_event_loop_work(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    adapter._recovery_runtime_ready = lambda request, body: True

    async def fake_execute(owner, launch, *, _api_server):
        return None

    monkeypatch.setattr(api_server_runs, "_execute_run", fake_execute)
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    lock_conn = sqlite3.connect(tmp_path / "state.db", check_same_thread=False)
    lock_conn.execute("BEGIN IMMEDIATE")
    released = threading.Event()

    def release_writer():
        lock_conn.rollback()
        released.set()

    timer = threading.Timer(0.4, release_writer)
    try:
        async with TestClient(TestServer(app)) as client:
            timer.start()
            task = asyncio.create_task(client.post("/v1/runs", json={
                "input": "hello", "session_id": "exact-session",
                "recovery": {"schema": "hermes.recovery/v1", "generation": 0, "parent_run_id": None},
            }, headers={"Idempotency-Key": "byf-recovery-v1:one"}))
            started = asyncio.get_running_loop().time()
            await asyncio.sleep(0.05)
            assert asyncio.get_running_loop().time() - started < 0.2
            assert (await task).status == 202
    finally:
        timer.join(timeout=1)
        if not released.is_set():
            lock_conn.rollback()
        lock_conn.close()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("second_protected", [False, True])
async def test_pending_protected_reservation_holds_concurrency_slot(
        tmp_path: Path, monkeypatch, second_protected: bool):
    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    adapter._max_concurrent_runs = 1
    adapter._recovery_runtime_ready = lambda request, body: True
    entered = threading.Event()
    release = threading.Event()
    original_reserve = RecoveryStore.reserve

    def held_reserve(store, admission, identity):
        entered.set()
        assert release.wait(timeout=3)
        return original_reserve(store, admission, identity)

    async def fake_execute(owner, launch, *, _api_server):
        return None

    monkeypatch.setattr(RecoveryStore, "reserve", held_reserve)
    monkeypatch.setattr(api_server_runs, "_execute_run", fake_execute)
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    body = {"input": "hello", "session_id": "exact-session",
            "recovery": {"schema": "hermes.recovery/v1", "generation": 0, "parent_run_id": None}}
    first = None
    try:
        async with TestClient(TestServer(app)) as client:
            first = asyncio.create_task(client.post(
                "/v1/runs", json=body, headers={"Idempotency-Key": "byf-recovery-v1:one"}))
            assert await asyncio.to_thread(entered.wait, 2)
            next_body = body if second_protected else {"input": "ordinary"}
            next_headers = {"Idempotency-Key": "byf-recovery-v1:two"} if second_protected else {}
            second = await client.post("/v1/runs", json=next_body, headers=next_headers)
            assert second.status == 429
            release.set()
            assert (await first).status == 202
    finally:
        release.set()
        if first is not None and not first.done():
            await first
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_ordinary_run_body_above_protected_limit_retains_legacy_admission(monkeypatch):
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))

    async def fake_execute(owner, launch, *, _api_server):
        return None

    monkeypatch.setattr(api_server_runs, "_execute_run", fake_execute)
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    try:
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/v1/runs", json={"input": "x" * (16 * 1024 + 1)})
            assert response.status == 202
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "completed", "stopping"])
async def test_protected_status_writer_lock_keeps_loop_live(tmp_path: Path, status: str):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    assert store.reserve(_root(), identity).outcome == "created"
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    lock_conn = sqlite3.connect(tmp_path / "state.db", check_same_thread=False)
    lock_conn.execute("BEGIN IMMEDIATE")
    timer = threading.Timer(0.35, lock_conn.rollback)
    tick = asyncio.Event()
    try:
        timer.start()
        asyncio.get_running_loop().call_later(0.05, tick.set)
        adapter._set_run_status(identity.run_id, status)
        await asyncio.wait_for(tick.wait(), timeout=0.2)
        await api_server_runs._await_protected_status(adapter, identity.run_id)
        assert store.status_for_run(identity.scope.profile, identity.scope.scope_digest,
                                    identity.run_id)["status"] == status
    finally:
        timer.join(timeout=1)
        lock_conn.rollback()
        lock_conn.close()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_protected_status_writes_order_and_surface_failure(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    entered = threading.Event()
    release = threading.Event()
    written: list[str] = []
    original_update = store.update_status

    def held_update(run_id: str, current: dict):
        if current["status"] == "running":
            entered.set()
            assert release.wait(timeout=3)
        original_update(run_id, current)
        written.append(current["status"])

    monkeypatch.setattr(store, "update_status", held_update)
    try:
        adapter._set_run_status(identity.run_id, "running")
        assert await asyncio.to_thread(entered.wait, 2)
        adapter._set_run_status(identity.run_id, "completed")
        release.set()
        await api_server_runs._await_protected_status(adapter, identity.run_id)
        assert written == ["running", "completed"]
        assert store.status_for_run(identity.scope.profile, identity.scope.scope_digest,
                                    identity.run_id)["status"] == "completed"

        def failed_update(run_id: str, current: dict):
            raise sqlite3.OperationalError("deliberate status write failure")

        monkeypatch.setattr(store, "update_status", failed_update)
        adapter._set_run_status(identity.run_id, "stopping")
        with pytest.raises(sqlite3.OperationalError, match="deliberate status write failure"):
            await api_server_runs._await_protected_status(adapter, identity.run_id)
        adapter._set_run_status(identity.run_id, "cancelled")
        with pytest.raises(sqlite3.OperationalError, match="deliberate status write failure"):
            await api_server_runs._await_protected_status(adapter, identity.run_id)
        assert written == ["running", "completed"]
    finally:
        release.set()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_cancelled_status_waiter_keeps_worker_and_order(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    entered = threading.Event()
    release = threading.Event()
    written: list[str] = []
    original_update = store.update_status

    def held_update(run_id: str, current: dict):
        if current["status"] == "running":
            entered.set()
            assert release.wait(timeout=3)
        original_update(run_id, current)
        written.append(current["status"])

    monkeypatch.setattr(store, "update_status", held_update)
    try:
        adapter._set_run_status(identity.run_id, "running")
        assert await asyncio.to_thread(entered.wait, 2)
        waiter = asyncio.create_task(adapter._await_protected_run_status(identity.run_id))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not adapter._protected_status_tasks[identity.run_id].done()
        adapter._set_run_status(identity.run_id, "completed")
        release.set()
        await adapter._await_protected_run_status(identity.run_id)
        assert written == ["running", "completed"]
    finally:
        release.set()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_protected_stop_route_keeps_loop_live_while_status_writer_waits(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    adapter._run_statuses[identity.run_id] = {"status": "running"}
    fake_task = asyncio.create_task(asyncio.sleep(2))
    monkeypatch.setattr(api_server_runs, "_load_owned_run", lambda *args, **kwargs: (
        identity.run_id, adapter._run_statuses[identity.run_id], None, fake_task, None))
    app = web.Application()
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    lock_conn = sqlite3.connect(tmp_path / "state.db", check_same_thread=False)
    lock_conn.execute("BEGIN IMMEDIATE")
    timer = threading.Timer(0.35, lock_conn.rollback)
    tick = asyncio.Event()
    try:
        async with TestClient(TestServer(app)) as client:
            timer.start()
            asyncio.get_running_loop().call_later(0.05, tick.set)
            response_task = asyncio.create_task(client.post(f"/v1/runs/{identity.run_id}/stop"))
            await asyncio.wait_for(tick.wait(), timeout=0.2)
            response = await response_task
            assert response.status == 200
            assert store.status_for_run(identity.scope.profile, identity.scope.scope_digest,
                                        identity.run_id)["status"] == "stopping"
    finally:
        timer.join(timeout=1)
        lock_conn.rollback()
        lock_conn.close()
        fake_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await fake_task
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_status_join_waits_for_new_tail_added_during_join(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    first_entered, first_release = threading.Event(), threading.Event()
    second_entered, second_release = threading.Event(), threading.Event()
    original_update = store.update_status

    def held_update(run_id: str, current: dict):
        if current["status"] == "running":
            first_entered.set()
            assert first_release.wait(timeout=3)
        if current["status"] == "completed":
            second_entered.set()
            assert second_release.wait(timeout=3)
        original_update(run_id, current)

    monkeypatch.setattr(store, "update_status", held_update)
    try:
        adapter._set_run_status(identity.run_id, "running")
        assert await asyncio.to_thread(first_entered.wait, 2)
        waiter = asyncio.create_task(adapter._await_protected_run_status(identity.run_id))
        await asyncio.sleep(0)
        adapter._set_run_status(identity.run_id, "completed")
        first_release.set()
        assert await asyncio.to_thread(second_entered.wait, 2)
        assert not waiter.done()
        second_release.set()
        await waiter
        assert store.status_for_run(identity.scope.profile, identity.scope.scope_digest,
                                    identity.run_id)["status"] == "completed"
    finally:
        first_release.set()
        second_release.set()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_protected_executor_waits_for_running_status_before_dispatch(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    adapter._recovery_runtime_ready = lambda request, body: True
    entered, release = threading.Event(), threading.Event()
    created = threading.Event()
    original_update = RecoveryStore.update_status

    def held_update(store, run_id: str, current: dict):
        if current["status"] == "running":
            entered.set()
            assert release.wait(timeout=3)
        return original_update(store, run_id, current)

    def fake_create_agent(**kwargs):
        created.set()
        return SimpleNamespace()

    monkeypatch.setattr(RecoveryStore, "update_status", held_update)
    monkeypatch.setattr(adapter, "_create_agent", fake_create_agent)
    monkeypatch.setattr(api_server_runs, "_run_agent_sync", lambda *args, **kwargs: (
        {"final_response": "done"}, {}))
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    try:
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/v1/runs", json={
                "input": "hello", "session_id": "exact-session",
                "recovery": {"schema": "hermes.recovery/v1", "generation": 0, "parent_run_id": None},
            }, headers={"Idempotency-Key": "byf-recovery-v1:one"})
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            assert await asyncio.to_thread(entered.wait, 2)
            assert not created.is_set()
            release.set()
            for _ in range(100):
                if adapter._run_statuses[run_id]["status"] == "completed":
                    break
                await asyncio.sleep(0.01)
            assert created.is_set()
            await adapter._await_protected_run_status(run_id)
            assert adapter._run_statuses[run_id]["status"] == "completed"
            store = RecoveryStore(db)
            assert store.status_for_run("default", adapter._run_owners[run_id], run_id)["status"] == "completed"
    finally:
        release.set()
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("write_fails", [False, True])
async def test_stop_terminal_status_waits_for_protected_write(tmp_path: Path, monkeypatch,
                                                              write_fails: bool):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    identity = _identity(store, owner=current_incarnation())
    store.reserve(_root(), identity)
    adapter = api_server.APIServerAdapter(PlatformConfig(enabled=True))
    adapter._protected_run_ids.add(identity.run_id)
    adapter._protected_run_stores[identity.run_id] = store
    adapter._run_statuses[identity.run_id] = {"status": "running"}
    entered, release = threading.Event(), threading.Event()
    original_update = store.update_status

    def held_terminal_write(run_id: str, current: dict):
        entered.set()
        assert release.wait(timeout=3)
        if write_fails:
            raise sqlite3.OperationalError("terminal status write failed")
        return original_update(run_id, current)

    monkeypatch.setattr(store, "update_status", held_terminal_write)
    monkeypatch.setattr(api_server_runs, "_load_owned_run", lambda *args, **kwargs: (
        identity.run_id, adapter._run_statuses[identity.run_id], None, None, None))
    app = web.Application()
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    try:
        async with TestClient(TestServer(app)) as client:
            adapter._set_run_status(identity.run_id, "completed", output="done")
            assert await asyncio.to_thread(entered.wait, 2)
            response_task = asyncio.create_task(client.post(f"/v1/runs/{identity.run_id}/stop"))
            await asyncio.sleep(0.05)
            assert not response_task.done()
            release.set()
            response = await response_task
            assert response.status == (503 if write_fails else 200)
            if write_fails:
                assert (await response.json())["error"]["code"] == "recovery_status_unavailable"
            else:
                assert (await response.json())["status"] == "completed"
                assert store.status_for_run(identity.scope.profile, identity.scope.scope_digest,
                                            identity.run_id)["status"] == "completed"
    finally:
        release.set()
        await adapter.disconnect()
        db.close()
