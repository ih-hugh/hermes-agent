"""Alternate gateway construction cannot adopt a protected session by ID."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.recovery_context import bind_write_permit, issue_write_permit
from agent.recovery_producers import bind_registry
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms import api_server_runs
from hermes_state_recovery import RecoveryRefused
from tests.agent.test_recovery_runtime import _admitted
from tests.recovery_provider_fixture import selected_provider


def test_protected_agent_construction_requires_exact_registry_and_write_permit(tmp_path):
    db, _store, scope, registry = _admitted(tmp_path)
    adapter = APIServerAdapter.__new__(APIServerAdapter)
    adapter._session_db = db
    adapter._ensure_session_db = lambda: pytest.fail("DB opened before construction claim")
    permit = issue_write_permit(
        registry.permit, registry.store, registry.scope, registry.run_id,
        registry.generation)
    try:
        adapter._assert_recovery_agent_construction("ordinary-session")
        with pytest.raises(RecoveryRefused):
            adapter._assert_recovery_agent_construction(scope.session_id)
        with bind_write_permit(permit):
            with pytest.raises(RecoveryRefused):
                adapter._assert_recovery_agent_construction(scope.session_id)
        with bind_registry(registry):
            with pytest.raises(RecoveryRefused):
                adapter._assert_recovery_agent_construction(scope.session_id)
            with bind_write_permit(permit):
                with pytest.raises(RecoveryRefused):
                    adapter._assert_recovery_agent_construction(scope.session_id)
                lease = registry.enter(registry.permit, "executor")
                lease.run(lambda: adapter._assert_recovery_agent_construction(scope.session_id))
    finally:
        db.close()


def test_unavailable_authority_refuses_before_agent_construction(tmp_path, monkeypatch):
    adapter = APIServerAdapter.__new__(APIServerAdapter)
    adapter._session_db = None
    (tmp_path / "state.db").write_bytes(b"not sqlite")
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: tmp_path)
    adapter._ensure_session_db = lambda: pytest.fail("DB opened before claim")
    constructed = []
    monkeypatch.setattr(adapter, "_select_agent_runtime", lambda *a, **kw: constructed.append(True))
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        adapter._create_agent(session_id="protected-session")
    assert not constructed


@pytest.mark.asyncio
async def test_protected_construction_does_not_block_gateway_loop(tmp_path, monkeypatch):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    adapter._session_db = db
    adapter._recovery_runtime_ready = lambda request, body: True
    selected_provider(monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def held_construction(**kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return SimpleNamespace()

    monkeypatch.setattr(adapter, "_create_agent", held_construction)
    monkeypatch.setattr(api_server_runs, "_run_agent_sync", lambda *args, **kwargs: (
        {"final_response": "done"}, {}))
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    try:
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/v1/runs", json={
                "input": "hello", "session_id": "exact-session",
                "recovery": {"schema": "hermes.recovery/v1", "generation": 0,
                             "parent_run_id": None},
            }, headers={"Idempotency-Key": "byf-recovery-v1:construction"})
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            assert await asyncio.to_thread(entered.wait, 2)
            loop_advanced = asyncio.Event()
            asyncio.get_running_loop().call_soon(loop_advanced.set)
            await asyncio.wait_for(loop_advanced.wait(), timeout=0.5)
            assert adapter._run_statuses[run_id]["status"] == "running"
            release.set()
            for _ in range(100):
                if adapter._run_statuses[run_id]["status"] == "completed":
                    break
                await asyncio.sleep(0.01)
            assert adapter._run_statuses[run_id]["status"] == "completed"
    finally:
        release.set()
        await adapter.disconnect()
        db.close()
