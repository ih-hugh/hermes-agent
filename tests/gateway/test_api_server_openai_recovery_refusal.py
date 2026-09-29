"""Unsupported OpenAI-compatible routes refuse protected identities before provider work."""

from __future__ import annotations

import sqlite3

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from tests.agent.test_recovery_runtime import _admitted


def _initialize_protected_route(
    db, store, scope, registry, *,
    session_key: str | None = None,
    parent_session_id: str | None = None,
) -> None:
    from agent.recovery_context import bind_write_permit, issue_write_permit

    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation)
    executor = registry.enter(registry.permit, "executor")

    def initialize() -> None:
        db.initialize_protected_session(
            scope.session_id, "api_server", recovery_permit=writer,
            profile_name=scope.profile, session_key=session_key,
            parent_session_id=parent_session_id,
        )

    with bind_write_permit(writer):
        executor.run(initialize)
    assert tuple(db._read_one(
        "SELECT session_key, parent_session_id FROM sessions WHERE id=?",
        (scope.session_id,),
    )) == (session_key, parent_session_id)


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
        db.create_session("ordinary", "api_server")
        db.end_session("ordinary", "compression")
        _initialize_protected_route(
            db, _store, scope, _registry, parent_session_id="ordinary")
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
    db, store, scope, registry = _admitted(tmp_path)
    if route == "chat_tip":
        db.create_session("ordinary", "api_server")
        db.end_session("ordinary", "compression")
    _initialize_protected_route(
        db, store, scope, registry,
        parent_session_id="ordinary" if route == "chat_tip" else None,
        session_key="route-key" if route == "responses_alias" else None,
    )
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


@pytest.mark.asyncio
async def test_broken_compression_read_refuses_before_writable_init(tmp_path, monkeypatch):
    from hermes_recovery_refusal import readonly_resume_session
    from hermes_state_recovery import RecoveryRefused

    db, store, scope, registry = _admitted(tmp_path)
    db.create_session("ordinary", "api_server")
    db.end_session("ordinary", "compression")
    _initialize_protected_route(
        db, store, scope, registry, parent_session_id="ordinary")
    db.close()
    with sqlite3.connect(tmp_path / "state.db") as conn:
        conn.execute("ALTER TABLE sessions RENAME COLUMN source TO source_broken")
        conn.execute("DROP TABLE async_delegations")
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: tmp_path)
    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        readonly_resume_session("ordinary", db_path=tmp_path / "state.db")

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "k"}))
    opened = []
    monkeypatch.setattr(adapter, "_ensure_session_db_async",
                        lambda: opened.append(True) or pytest.fail("writable SessionDB opened"))
    monkeypatch.setattr(adapter, "_select_request_route",
                        lambda *a, **kw: pytest.fail("provider route selected"))
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    try:
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/v1/chat/completions", json={
                "model": "hermes", "messages": [{"role": "user", "content": "hello"}]},
                headers={"Authorization": "Bearer k", "X-Hermes-Session-Id": "ordinary"})
            assert response.status == 409
            assert not opened
    finally:
        await adapter.disconnect()
    with sqlite3.connect(tmp_path / "state.db") as conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='async_delegations'").fetchone() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["chat", "responses"])
async def test_generated_session_claim_precedes_provider_selection(tmp_path, monkeypatch, route):
    from hermes_state import SessionDB

    db = SessionDB(tmp_path / "state.db")
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "k"}))
    adapter._session_db = db
    selected: list[str] = []

    def assert_claimed(*_args, **kwargs):
        session_id = kwargs["session_id"]
        with sqlite3.connect(tmp_path / "state.db") as conn:
            assert conn.execute(
                "SELECT 1 FROM recovery_exclusions WHERE kind='ordinary_session' AND session_id=?",
                (session_id,),
            ).fetchone() == (1,)
        selected.append(session_id)
        return None, {}, web.Response(status=418)

    monkeypatch.setattr(adapter, "_select_request_route", assert_claimed)
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    app.router.add_post("/v1/responses", adapter._handle_responses)
    try:
        async with TestClient(TestServer(app)) as client:
            if route == "chat":
                response = await client.post("/v1/chat/completions", json={
                    "model": "hermes", "messages": [{"role": "user", "content": "hello"}]},
                    headers={"Authorization": "Bearer k"})
            else:
                response = await client.post("/v1/responses", json={"input": "hello"},
                                             headers={"Authorization": "Bearer k"})
            assert response.status == 418
            assert len(selected) == 1
    finally:
        await adapter.disconnect()
        db.close()
