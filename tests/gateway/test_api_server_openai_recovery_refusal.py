"""Unsupported OpenAI-compatible routes refuse protected identities before provider work."""

from __future__ import annotations

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from tests.agent.test_recovery_runtime import _admitted


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["chat_original", "chat_resolved", "responses_chain"])
async def test_alternate_route_refuses_before_selection_or_agent(tmp_path, monkeypatch, path):
    db, _store, scope, _registry = _admitted(tmp_path)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "k"}))
    adapter._session_db = db
    monkeypatch.setattr(adapter, "_select_request_route",
                        lambda *a, **kw: pytest.fail("provider route selected"))
    monkeypatch.setattr(adapter, "_run_agent",
                        lambda *a, **kw: pytest.fail("agent task started"))
    if path == "chat_resolved":
        monkeypatch.setattr(db, "resolve_resume_session_id", lambda sid: scope.session_id)
    if path == "responses_chain":
        adapter._response_store.put("resp_prior", {
            "session_id": scope.session_id, "conversation_history": []})
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    app.router.add_post("/v1/responses", adapter._handle_responses)
    try:
        async with TestClient(TestServer(app)) as client:
            if path == "responses_chain":
                response = await client.post("/v1/responses", json={
                    "input": "hello", "previous_response_id": "resp_prior"},
                    headers={"Authorization": "Bearer k"})
            else:
                response = await client.post("/v1/chat/completions", json={
                    "model": "hermes", "messages": [{"role": "user", "content": "hello"}]},
                    headers={"Authorization": "Bearer k", "X-Hermes-Session-Id": (
                        scope.session_id if path == "chat_original" else "ordinary")})
            assert response.status == 409
    finally:
        await adapter.disconnect()
        db.close()
