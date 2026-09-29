"""Unsupported OpenAI-compatible routes refuse protected identities before provider work."""

from __future__ import annotations

import sqlite3

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
        from agent.recovery_context import bind_write_permit, issue_write_permit

        db.create_session("ordinary", "api_server")
        db.end_session("ordinary", "compression")
        writer = issue_write_permit(
            _registry.permit, _store, scope, _registry.run_id, _registry.generation)
        with bind_write_permit(writer):
            db.create_session(scope.session_id, "api_server", parent_session_id="ordinary")
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


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["responses_alias", "chat_tip"])
async def test_protected_alias_or_tip_refuses_before_writable_init(tmp_path, monkeypatch, route):
    from agent.recovery_context import bind_write_permit, issue_write_permit

    db, store, scope, registry = _admitted(tmp_path)
    if route == "chat_tip":
        db.create_session("ordinary", "api_server")
        db.end_session("ordinary", "compression")
    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server",
                          **({"parent_session_id": "ordinary"} if route == "chat_tip"
                             else {"session_key": "route-key"}))
    db.close()
    with sqlite3.connect(tmp_path / "state.db") as conn:
        conn.execute("DROP TABLE async_delegations")
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: tmp_path)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "k"}))
    monkeypatch.setattr(adapter, "_ensure_session_db_async",
                        lambda: pytest.fail("writable SessionDB opened"))
    monkeypatch.setattr(adapter, "_select_request_route",
                        lambda *a, **kw: pytest.fail("provider route selected"))
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    app.router.add_post("/v1/responses", adapter._handle_responses)
    try:
        async with TestClient(TestServer(app)) as client:
            if route == "responses_alias":
                response = await client.post("/v1/responses", json={"input": "hello"},
                    headers={"Authorization": "Bearer k", "X-Hermes-Session-Key": "route-key"})
            else:
                response = await client.post("/v1/chat/completions", json={
                    "model": "hermes", "messages": [{"role": "user", "content": "hello"}]},
                    headers={"Authorization": "Bearer k", "X-Hermes-Session-Id": "ordinary"})
            assert response.status == 409
    finally:
        await adapter.disconnect()
    with sqlite3.connect(tmp_path / "state.db") as conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is None
