"""Private readback and admission rules for names-v1 tool diagnostics."""

import asyncio
import threading
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.tool_diagnostic import ToolSendObserver
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


@pytest.mark.asyncio
async def test_owner_readback_and_expired_tombstone():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "one-key"}))
    app = web.Application()
    app.router.add_get(
        "/v1/runs/{run_id}/tool-diagnostic", adapter._handle_run_tool_diagnostic
    )
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        req = type(
            "Request", (), {"headers": {}, "path": "/v1/runs/run_x/tool-diagnostic"}
        )()
        scope = adapter._run_idempotency_scope(req)
        observer = ToolSendObserver("run_x", "default", scope, 123, 456)
        observer.capture_sdk_send(
            "send_x",
            "chat_completions",
            "main",
            [],
            deferred_tool_names=(),
            tool_search_active=False,
        )
        observer.close_producer()
        adapter._run_tool_diagnostics["run_x"] = observer
        headers = {"Authorization": "Bearer one-key"}
        response = await client.get("/v1/runs/run_x/tool-diagnostic", headers=headers)
        assert response.status == 200
        body = await response.json()
        assert body["state"] == "complete"
        assert body["attempts"][0]["tool_search_active"] is False
        assert (await client.get("/v1/runs/run_x/tool-diagnostic")).status == 401
        assert (
            await client.get(
                "/v1/runs/run_x/tool-diagnostic",
                headers={**headers, "X-Hermes-Room-Grant": "room-token"},
            )
        ).status == 401
        with patch.object(adapter, "_expected_api_key", return_value="rotated-key"):
            assert (
                await client.get(
                    "/v1/runs/run_x/tool-diagnostic",
                    headers={"Authorization": "Bearer rotated-key"},
                )
            ).status == 404
        adapter._sweep_orphaned_runs_once(observer.closed_at + 901)
        response = await client.get("/v1/runs/run_x/tool-diagnostic", headers=headers)
        assert response.status == 410
        assert "advertised_tool_names" not in await response.text()
        adapter._sweep_orphaned_runs_once(observer.closed_at + 1801)
        assert (
            await client.get("/v1/runs/run_x/tool-diagnostic", headers=headers)
        ).status == 404
    finally:
        await client.close()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_admission_version_process_guard_and_opt_out(tmp_path, monkeypatch):
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "one-key"}))
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    client = TestClient(TestServer(app))
    await client.start_server()
    headers = {"Authorization": "Bearer one-key"}
    try:
        unsupported = await client.post(
            "/v1/runs",
            json={"input": "hello", "diagnostics": {"tool_inventory": "names-v2"}},
            headers=headers,
        )
        assert unsupported.status == 400
        assert adapter._run_tool_diagnostics == {}
        old_start = adapter._run_owner_started
        adapter._run_owner_started = 0
        missing_start = await client.post(
            "/v1/runs",
            json={"input": "hello", "diagnostics": {"tool_inventory": "names-v1"}},
            headers=headers,
        )
        assert missing_start.status == 503
        adapter._run_owner_started = old_start
        monkeypatch.setattr("gateway.platforms.api_server_tool_diagnostic._MAX_RUNS", 0)
        full = await client.post(
            "/v1/runs",
            json={"input": "hello", "diagnostics": {"tool_inventory": "names-v1"}},
            headers=headers,
        )
        assert full.status == 429
        assert adapter._run_tool_diagnostics == {}
        monkeypatch.setattr(
            "gateway.platforms.api_server_tool_diagnostic._MAX_RUNS", 256
        )
        mock_agent = MagicMock()
        mock_agent.run_conversation.return_value = {"final_response": "done"}
        mock_agent.session_prompt_tokens = mock_agent.session_completion_tokens = (
            mock_agent.session_total_tokens
        ) = 0
        with patch.object(adapter, "_create_agent", return_value=mock_agent):
            opted_out = await client.post(
                "/v1/runs", json={"input": "hello"}, headers=headers
            )
            assert opted_out.status == 202
            assert adapter._run_tool_diagnostics == {}
            key_headers = {**headers, "Idempotency-Key": "toggle-diagnostic"}
            keyed = await client.post(
                "/v1/runs", json={"input": "same"}, headers=key_headers
            )
            assert keyed.status == 202
            toggled = await client.post(
                "/v1/runs",
                json={"input": "same", "diagnostics": {"tool_inventory": "names-v1"}},
                headers=key_headers,
            )
            assert toggled.status == 409
            assert adapter._run_tool_diagnostics == {}
            opted_in = await client.post(
                "/v1/runs",
                json={"input": "hello", "diagnostics": {"tool_inventory": "names-v1"}},
                headers=headers,
            )
            assert opted_in.status == 202
            run_id = (await opted_in.json())["run_id"]
            for _ in range(30):
                observer = adapter._run_tool_diagnostics[run_id]
                if observer.closed_at is not None:
                    break
                await asyncio.sleep(0.01)
            assert (
                observer.snapshot()["state"] == "incomplete"
            )  # mock agent made no SDK send
    finally:
        await client.close()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_cancelled_awaiting_task_does_not_close_executor_producer():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "one-key"}))
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get(
        "/v1/runs/{run_id}/tool-diagnostic", adapter._handle_run_tool_diagnostic
    )
    client = TestClient(TestServer(app))
    await client.start_server()
    started = threading.Event()
    release = threading.Event()
    agent = MagicMock()
    agent.tools = []
    agent.api_mode = "chat_completions"
    agent.provider = "nous"
    agent.enabled_toolsets = ["terminal", "file", "todo", "no_mcp"]
    from tools.registry import registry

    agent._tool_snapshot_generation = registry._generation

    def run_conversation(**_kwargs):
        agent._tool_send_observer.capture_sdk_send(
            "send_blocked",
            "chat_completions",
            "main",
            [],
            deferred_tool_names=(),
            tool_search_active=False,
        )
        started.set()
        release.wait(timeout=5)
        return {"final_response": "done"}

    agent.run_conversation.side_effect = run_conversation
    agent.session_prompt_tokens = agent.session_completion_tokens = (
        agent.session_total_tokens
    ) = 0
    try:

        def create_agent(**kwargs):
            adapter._run_tool_diagnostics[kwargs["session_id"]].set_tool_scope(
                (), (), False
            )
            return agent

        with patch.object(adapter, "_create_agent", side_effect=create_agent):
            response = await client.post(
                "/v1/runs",
                json={"input": "hello", "diagnostics": {"tool_inventory": "names-v1"}},
                headers={"Authorization": "Bearer one-key"},
            )
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            assert await asyncio.to_thread(started.wait, 2)
            adapter._active_run_tasks[run_id].cancel()
            for _ in range(30):
                if run_id not in adapter._active_run_tasks:
                    break
                await asyncio.sleep(0.01)
            pending = await client.get(
                f"/v1/runs/{run_id}/tool-diagnostic",
                headers={"Authorization": "Bearer one-key"},
            )
            assert (await pending.json())["state"] == "pending"
            release.set()
            for _ in range(30):
                settled = await client.get(
                    f"/v1/runs/{run_id}/tool-diagnostic",
                    headers={"Authorization": "Bearer one-key"},
                )
                if (await settled.json())["state"] == "complete":
                    break
                await asyncio.sleep(0.01)
            assert (await settled.json())["state"] == "complete"
    finally:
        release.set()
        await client.close()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_agent_construction_failure_closes_incomplete_diagnostic():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "one-key"}))
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        with patch.object(
            adapter, "_create_agent", side_effect=RuntimeError("private")
        ):
            response = await client.post(
                "/v1/runs",
                json={"input": "hello", "diagnostics": {"tool_inventory": "names-v1"}},
                headers={"Authorization": "Bearer one-key"},
            )
            assert response.status == 202
            run_id = (await response.json())["run_id"]
            for _ in range(30):
                observer = adapter._run_tool_diagnostics[run_id]
                if observer.closed_at is not None:
                    break
                await asyncio.sleep(0.01)
            assert observer.snapshot()["state"] == "incomplete"
            assert observer.snapshot()["reason"] == "unclosed_producer"
    finally:
        await client.close()
        await adapter.disconnect()
