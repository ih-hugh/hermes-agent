"""Compatibility seams for extracted RoomLink dispatch handling."""

import json
import sqlite3
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.platforms import api_server
from gateway.platforms import api_server_room_dispatch as room_dispatch


def test_api_server_keeps_room_dispatch_methods_on_the_adapter_class():
    assert {
        "_ensure_hosted_member_session",
        "_normalize_room_dispatch",
    } <= api_server.APIServerAdapter.__dict__.keys()


@pytest.mark.asyncio
async def test_hidden_member_session_method_delegates(monkeypatch):
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    dispatch = object()
    implementation = AsyncMock(return_value="room_session")
    monkeypatch.setattr(
        room_dispatch,
        "_ensure_hosted_member_session",
        implementation,
    )

    assert await adapter._ensure_hosted_member_session(dispatch) == "room_session"
    implementation.assert_awaited_once_with(adapter, dispatch)


@pytest.mark.asyncio
async def test_room_dispatch_normalizer_method_delegates(monkeypatch):
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    request = object()
    body = {"input": "hello"}
    expected = ({"input": "normalized"}, None)
    implementation = AsyncMock(return_value=expected)
    monkeypatch.setattr(room_dispatch, "_normalize_room_dispatch", implementation)

    assert await adapter._normalize_room_dispatch(request, body) == expected
    implementation.assert_awaited_once_with(
        adapter,
        request,
        body,
        _api_server=sys.modules[api_server.__name__],
    )


@pytest.mark.asyncio
async def test_non_room_run_body_passes_through_unchanged():
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    adapter._room_grant_token = MagicMock(return_value="")
    request = object()
    body = {"input": "ordinary run"}

    normalized, error = await adapter._normalize_room_dispatch(request, body)

    assert normalized is body
    assert error is None
    adapter._room_grant_token.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_partial_recovery_catalog_refuses_hidden_room_before_db_or_ddl(tmp_path, monkeypatch):
    dispatch = SimpleNamespace(home_install_id="home", room_id="room",
                               member_id="member", target_profile="default")
    session_id = room_dispatch._hosted_member_session_id(dispatch)
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE recovery_sessions(session_id TEXT PRIMARY KEY, phase TEXT, root_run_id TEXT)")
        conn.execute("CREATE TABLE recovery_members(run_id TEXT PRIMARY KEY, session_id TEXT, producer_state TEXT)")
        conn.execute("INSERT INTO recovery_sessions VALUES(?, 'sealed', 'run')", (session_id,))
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: tmp_path)
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    adapter._session_db = None
    adapter._ensure_session_db_async = AsyncMock(side_effect=AssertionError("DB opened"))
    with pytest.raises(ValueError, match="protected_session_authority_unavailable"):
        await room_dispatch._ensure_hosted_member_session(adapter, dispatch)
    adapter._ensure_session_db_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_hidden_room_claim_commits_before_session_writer(tmp_path, monkeypatch):
    from hermes_state import SessionDB
    from hermes_recovery_dispatch import selected_state_db_path

    db = SessionDB(tmp_path / "state.db")
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    adapter._session_db = db
    dispatch = SimpleNamespace(home_install_id="home", room_id="room",
                               member_id="member", target_profile="default")
    session_id = room_dispatch._hosted_member_session_id(dispatch)

    async def before_writer():
        with sqlite3.connect(selected_state_db_path(db)) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions WHERE session_id=?", (session_id,)
            ).fetchone() == (1,)
        return db

    adapter._ensure_session_db_async = before_writer
    try:
        assert await room_dispatch._ensure_hosted_member_session(adapter, dispatch) == session_id
    finally:
        db.close()


@pytest.mark.asyncio
async def test_room_dispatch_rejects_extra_fields_before_grant_verification():
    adapter = api_server.APIServerAdapter.__new__(api_server.APIServerAdapter)
    adapter._room_grant_token = MagicMock(return_value="room-grant")
    request = object()
    body = {
        "input": "room prompt",
        "hosted_room_dispatch": {},
        "unexpected": True,
    }

    normalized, error = await adapter._normalize_room_dispatch(request, body)

    assert normalized is body
    assert error.status == 400
    assert json.loads(error.text)["error"]["code"] == "invalid_room_dispatch"
