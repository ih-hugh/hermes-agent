"""Served protected run admission keeps request and owner authority exact."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import asyncio
import threading
import time
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import GatewayConfig, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from agent import secret_scope
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state_recovery_provider import SelectedProviderCapture
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore
from agent.recovery_context import current_incarnation
from agent.recovery_context import bind_write_permit
from agent.recovery_producers import bind_protected_constructor
from tests.recovery_provider_fixture import provider_admission


_KEY = "scratch-recovery-owner-key-12345"


def _app(adapter: APIServerAdapter) -> web.Application:
    async def probe(_request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    app = web.Application(middlewares=[adapter._make_profile_prefix_middleware()])
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/p/{profile}/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/scratch-loop-probe", probe)
    return app


@pytest.mark.asyncio
async def test_protected_waiter_cancel_keeps_reservation_and_third_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_runs

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    entered = asyncio.Event()
    both_entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def blocked(_adapter, _request, *, _api_server):
        nonlocal calls
        calls += 1
        entered.set()
        if calls == 2:
            both_entered.set()
        await release.wait()
        return web.json_response({"settled": True})

    monkeypatch.setattr(api_server_runs, "_handle_runs", blocked)
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": "byf-recovery-v1:retained",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            first = asyncio.create_task(
                client.post("/v1/runs", data=b"{}", headers=headers)
            )
            await asyncio.wait_for(entered.wait(), timeout=1)
            first.cancel()
            with suppress(asyncio.CancelledError):
                await first
            assert adapter._pending_agent_requests == 1
            second = asyncio.create_task(
                client.post("/v1/runs", data=b"{}", headers=headers)
            )
            await asyncio.wait_for(both_entered.wait(), timeout=1)
            third = await client.post("/v1/runs", data=b"{}", headers=headers)
            assert third.status == 429
            assert adapter._pending_agent_requests == 2
            release.set()
            assert (await second).status == 200
            await asyncio.sleep(0)
            assert adapter._pending_agent_requests == 0
    finally:
        release.set()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_protected_timeout_and_shutdown_retain_actual_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server, api_server_runs

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(api_server, "_PROTECTED_ADMISSION_SECONDS", 0.03)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked(_adapter, _request, *, _api_server):
        entered.set()
        await release.wait()
        return web.json_response({"settled": True})

    monkeypatch.setattr(api_server_runs, "_handle_runs", blocked)
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": "byf-recovery-v1:timeout",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post("/v1/runs", data=b"{}", headers=headers)
            assert response.status == 504
            assert entered.is_set()
            assert adapter._pending_agent_requests == 1
            shutting_down = asyncio.create_task(adapter.disconnect())
            await asyncio.sleep(0)
            assert not shutting_down.done()
            release.set()
            await asyncio.wait_for(shutting_down, timeout=1)
            assert adapter._pending_agent_requests == 0
    finally:
        release.set()


@pytest.mark.asyncio
async def test_duplicate_keyed_body_refuses_before_opening_state_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    config = home / "config.yaml"
    config.write_text("platforms:\n  api_server:\n    recovery:\n      enabled: true\n")
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    raw = (
        b'{"input":"first","input":"second","session_id":"protected",'
        b'"recovery":{"schema":"hermes.recovery/v1","generation":0,'
        b'"parent_run_id":null}}'
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                data=raw,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:duplicate",
                },
            )
            assert response.status == 400, await response.text()
        assert not (home / "state.db").exists()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_unready_new_key_does_not_initialize_state_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    raw = (
        b'{"input":"work","session_id":"protected",'
        b'"recovery":{"schema":"hermes.recovery/v1","generation":0,'
        b'"parent_run_id":null}}'
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                data=raw,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:unready",
                },
            )
            assert response.status == 503, await response.text()
            assert (await response.json())["error"]["code"] == (
                "recovery_runtime_unavailable"
            )
        assert not (home / "state.db").exists()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_unready_key_does_not_reconcile_ordinary_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    path = home / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE ordinary_sentinel(value TEXT NOT NULL)")
        conn.execute("INSERT INTO ordinary_sentinel VALUES('retained')")
    before = path.read_bytes()
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json={
                    "input": "work",
                    "session_id": "protected",
                    "recovery": {
                        "schema": "hermes.recovery/v1",
                        "generation": 0,
                        "parent_run_id": None,
                    },
                },
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:ordinary",
                },
            )
            assert response.status == 503, await response.text()
        assert path.read_bytes() == before
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT value FROM ordinary_sentinel").fetchall() == [
                ("retained",)
            ]
            assert (
                conn.execute(
                    "SELECT name FROM sqlite_master WHERE name='recovery_store'"
                ).fetchone()
                is None
            )
        assert not adapter._session_dbs
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_protected_session_id_utf8_bound_refuses_before_source_or_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    monkeypatch.setattr(
        adapter,
        "_open_and_cache_session_db",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("oversized session opened store")
        ),
    )
    monkeypatch.setattr(
        "hermes_state_recovery_provider.capture_selected_provider_admission",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("oversized session selected provider")
        ),
    )
    body = {
        "input": "work",
        "session_id": "🪁" * 64,
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json=body,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:oversized-session",
                },
            )
            assert response.status == 400, await response.text()
            assert (await response.json())["error"][
                "code"
            ] == "recovery_request_unsupported"
            assert not (home / "state.db").exists()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("session_id", ["protected", "🪁" * 63 + "abc"])
async def test_committed_key_replays_without_a_cached_writer_or_runtime_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session_id: str
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    config = home / "config.yaml"
    config.write_text("platforms:\n  api_server:\n    recovery:\n      enabled: true\n")
    body = {
        "input": "work",
        "session_id": session_id,
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    key = "byf-recovery-v1:committed"
    fingerprint = hashlib.sha256(
        json.dumps(
            {"body": body, "gateway_session_key": ""},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    digest = hashlib.sha256(f"default\0{_KEY}".encode()).hexdigest()
    db = SessionDB(home / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "default", digest, session_id)
    result = store.reserve(
        RecoveryAdmission.model_validate(body["recovery"]),
        AdmissionIdentity(
            scope,
            key,
            fingerprint,
            "run_committed",
            current_incarnation(),
            provider_admission(session_id),
            {"status": "queued"},
        ),
    )
    assert result.outcome == "created"
    db.close()
    config.write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: false\n"
    )

    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))

    def no_writer(_home: Path):
        raise AssertionError("committed replay opened a writable SessionDB")

    monkeypatch.setattr(adapter, "_open_and_cache_session_db", no_writer)
    monkeypatch.setattr(
        "hermes_state_recovery_provider.capture_selected_provider_admission",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("replay selected provider")
        ),
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json=body,
                headers={"Authorization": f"Bearer {_KEY}", "Idempotency-Key": key},
            )
            assert response.status == 202, await response.text()
            assert await response.json() == {
                "run_id": "run_committed",
                "status": "queued",
                "replayed": True,
            }
            changed = await client.post(
                "/v1/runs",
                json={**body, "instructions": "changed"},
                headers={"Authorization": f"Bearer {_KEY}", "Idempotency-Key": key},
            )
            assert changed.status == 409, await changed.text()
            assert (await changed.json())["error"]["code"] == "idempotency_key_conflict"
            new_key = await client.post(
                "/v1/runs",
                json=body,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:new-disabled",
                },
            )
            assert new_key.status == 503, await new_key.text()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra,headers",
    [
        ({"model_options": {}}, {}),
        ({"previous_response_id": "response_old"}, {}),
        ({"input": [{"role": "user", "content": "work"}]}, {}),
        ({"hosted_room_dispatch": {}}, {}),
        ({}, {"X-Hermes-Session-Key": "foreign"}),
    ],
)
async def test_protected_shape_refuses_before_room_normalization_or_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra: dict,
    headers: dict[str, str],
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))

    async def no_normalization(*_args, **_kwargs):
        raise AssertionError("protected request entered room normalization")

    monkeypatch.setattr(adapter, "_normalize_room_dispatch", no_normalization)
    body = {
        "input": "work",
        "session_id": "protected",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
        **extra,
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json=body,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:shape",
                    **headers,
                },
            )
            assert response.status == 400, await response.text()
        assert not (home / "state.db").exists()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_same_opaque_key_cannot_cross_physical_profile_before_or_after_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".hermes"
    named = root / "profiles" / "byf-builder"
    named.mkdir(parents=True)
    monkeypatch.setattr("hermes_cli.profiles._get_default_hermes_home", lambda: root)
    monkeypatch.setenv("HERMES_HOME", str(named))
    monkeypatch.setattr(
        "hermes_cli.profiles.profiles_to_serve",
        lambda multiplex: [("default", root), ("byf-builder", named)],
    )
    for home in (root, named):
        (home / ".env").write_text(f"API_SERVER_KEY={_KEY}\n")
        (home / "config.yaml").write_text(
            "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
        )
    digest = hashlib.sha256(f"default\0{_KEY}".encode()).hexdigest()
    for home, profile, run_id in (
        (root, "default", "run_default"),
        (named, "byf-builder", "run_named"),
    ):
        db = SessionDB(home / "state.db")
        store = RecoveryStore(db)
        scope = RecoveryScope(store.store_id, profile, digest, f"session_{profile}")
        result = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=0, parent_run_id=None
            ),
            AdmissionIdentity(
                scope,
                f"byf-recovery-v1:{run_id}",
                "a" * 64,
                run_id,
                current_incarnation(),
                provider_admission(scope.session_id),
                {"status": "queued", "run_id": run_id},
            ),
        )
        assert result.outcome == "created"
        db.close()
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    adapter.gateway_runner = SimpleNamespace(
        config=GatewayConfig(multiplex_profiles=True)
    )
    secret_scope.set_multiplex_active(True)
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            headers = {"Authorization": f"Bearer {_KEY}"}
            named_ok = await client.get("/v1/runs/run_named", headers=headers)
            assert named_ok.status == 200, await named_ok.text()
            default_wrong = await client.get(
                "/p/default/v1/runs/run_named", headers=headers
            )
            assert default_wrong.status == 404, await default_wrong.text()
            default_ok = await client.get(
                "/p/default/v1/runs/run_default", headers=headers
            )
            assert default_ok.status == 200, await default_ok.text()
            named_wrong = await client.get("/v1/runs/run_default", headers=headers)
            assert named_wrong.status == 404, await named_wrong.text()
            getattr(adapter, "_run_statuses").clear()
            getattr(adapter, "_run_owners").clear()
            getattr(adapter, "_protected_physical_owners").clear()
            repeated = await client.get("/p/default/v1/runs/run_named", headers=headers)
            assert repeated.status == 404, await repeated.text()
            repeated_ok = await client.get("/v1/runs/run_named", headers=headers)
            assert repeated_ok.status == 200, await repeated_ok.text()
            assert not adapter._session_dbs
    finally:
        secret_scope.set_multiplex_active(False)
        await adapter.disconnect()

    restarted = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    restarted.gateway_runner = SimpleNamespace(
        config=GatewayConfig(multiplex_profiles=True)
    )
    secret_scope.set_multiplex_active(True)
    try:
        async with TestClient(TestServer(_app(restarted))) as client:
            headers = {"Authorization": f"Bearer {_KEY}"}
            assert (
                await client.get("/p/default/v1/runs/run_named", headers=headers)
            ).status == 404
            assert (
                await client.get("/v1/runs/run_named", headers=headers)
            ).status == 200
            assert not restarted._session_dbs
    finally:
        secret_scope.set_multiplex_active(False)
        await restarted.disconnect()


def test_protected_gateway_constructor_uses_admitted_registry_db_without_opening_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.agent.test_recovery_constructor import _prepared

    _, db, scope, registry, _, prepared, writer, executor = _prepared(
        tmp_path, monkeypatch
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))

    def no_cache():
        raise AssertionError("protected constructor opened generic SessionDB")

    monkeypatch.setattr(adapter, "_ensure_session_db", no_cache)

    def construct():
        with bind_write_permit(writer), bind_protected_constructor(prepared):
            agent = adapter._create_agent(
                session_id=scope.session_id,
                protected_runtime=prepared,
            )
        try:
            assert agent._session_db is db
            assert agent._hermes_api_runtime == {
                "provider": prepared.provider,
                "model": prepared.model,
                "route_source": "protected_static",
            }
        finally:
            agent.client.close()

    try:
        executor.run(construct)
        assert not adapter._session_dbs
    finally:
        db.close()


@pytest.mark.asyncio
async def test_new_protected_reserve_uses_exact_prepared_route_and_replays_after_source_retires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime, api_server_runs
    import hermes_state_recovery_provider

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    selected = type("Selected", (), {})()
    calls: list[str] = []

    def prepare(owner, *, session_id):
        calls.append("prepare")
        return SimpleNamespace(
            profile=owner.profile,
            home=owner.home,
            scope_digest=owner.scope_digest,
            session_id=session_id,
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        )

    def capture(session_id, *, deadline):
        assert isinstance(deadline, float)
        calls.append("capture")
        return SelectedProviderCapture(provider_admission(session_id), selected)

    async def no_external_run(adapter, run, *, _api_server):
        run.recovery_execution_settled.set()
        run.recovery_registry.request_close()
        run.recovery_coroutine_settled.set()
        api_server_runs._retire_live_run(adapter, run.run_id)

    monkeypatch.setattr(
        api_server_recovery_runtime, "prepare_static_chat_runtime", prepare
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider, "capture_selected_provider_admission", capture
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    monkeypatch.setattr(api_server_runs, "_execute_run", no_external_run)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "protected",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": "byf-recovery-v1:new",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            accepted = await client.post("/v1/runs", json=body, headers=headers)
            assert accepted.status == 202, await accepted.text()
            first = await accepted.json()
            assert first["replayed"] is False
            assert calls == ["prepare", "capture"]
            db = adapter._session_dbs[str(home)]
            assert tuple(
                db._read_one(
                    "SELECT session_id FROM recovery_members WHERE run_id=?",
                    (first["run_id"],),
                )
            ) == ("protected",)

            def retired(_session_id, *, deadline):
                raise AssertionError("committed retry recaptured retired provider")

            monkeypatch.setattr(
                hermes_state_recovery_provider,
                "capture_selected_provider_admission",
                retired,
            )
            replay = await client.post("/v1/runs", json=body, headers=headers)
            assert replay.status == 202, await replay.text()
            assert await replay.json() == {
                "run_id": first["run_id"],
                "status": "queued",
                "replayed": True,
            }
    finally:
        await adapter.disconnect()


def test_root_existing_large_ordinary_history_is_not_loaded_before_reserve_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime, api_server_runs
    from gateway.platforms.api_server_recovery import RecoveryOwnerContext
    import hermes_state_recovery_provider

    home = tmp_path / "profile"
    home.mkdir()
    db = SessionDB(home / "state.db")
    db.create_session("ordinary-large", "api_server")
    db.append_message("ordinary-large", "user", "x" * (128 * 1024 + 1))
    adapter = SimpleNamespace(_open_and_cache_session_db=lambda _home: db)
    monkeypatch.setattr(
        api_server_runs,
        "_bounded_protected_history",
        lambda *_: (_ for _ in ()).throw(AssertionError("root read full history")),
    )
    selected = object()
    monkeypatch.setattr(
        api_server_recovery_runtime,
        "prepare_static_chat_runtime",
        lambda owner, *, session_id: SimpleNamespace(
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        ),
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda session_id, *, deadline: SelectedProviderCapture(
            provider_admission(session_id),
            selected,
        ),
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    owner = RecoveryOwnerContext("default", home, "b" * 64)
    body = {"session_id": "ordinary-large"}
    admission = RecoveryAdmission(
        schema="hermes.recovery/v1",
        generation=0,
        parent_run_id=None,
    )
    try:
        result = api_server_runs._prepare_and_reserve_protected(
            adapter,
            owner,
            body,
            admission,
            "byf-recovery-v1:ordinary-large",
            "a" * 64,
            "run_ordinary_large",
            {"status": "queued"},
            time.monotonic() + 5,
        )
        assert result.result.outcome == "refused"
        assert result.result.reason == "existing_session"
        member_count = db._read_one(
            "SELECT COUNT(*) FROM recovery_members WHERE session_id=?",
            ("ordinary-large",),
        )
        assert member_count is not None and member_count[0] == 0
    finally:
        db.close()


def test_nudge_history_bounds_source_before_payload_fetch_and_rolls_back_on_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime, api_server_runs
    from gateway.platforms.api_server_recovery import RecoveryOwnerContext
    import hermes_state_recovery_provider
    from hermes_state_recovery import RecoveryRefused
    from hermes_state_recovery_deadline import (
        RecoveryDeadlineExceeded,
        recovery_deadline,
    )
    import hermes_state_recovery_deadline

    db = SessionDB(tmp_path / "state.db")
    db.create_session("protected-nudge", "api_server")
    db.append_message("protected-nudge", "user", "x" * (128 * 1024 + 1))
    selected = object()
    monkeypatch.setattr(
        api_server_recovery_runtime,
        "prepare_static_chat_runtime",
        lambda owner, *, session_id: SimpleNamespace(
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        ),
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda session_id, *, deadline: SelectedProviderCapture(
            provider_admission(session_id),
            selected,
        ),
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    adapter = SimpleNamespace(_open_and_cache_session_db=lambda _home: db)
    owner = RecoveryOwnerContext("default", tmp_path, "b" * 64)
    admission = RecoveryAdmission(
        schema="hermes.recovery/v1",
        generation=1,
        parent_run_id="run_parent",
    )
    traced: list[str] = []
    connection = db._conn
    assert connection is not None
    connection.set_trace_callback(traced.append)
    try:
        deadline = time.monotonic() + 5
        with recovery_deadline(deadline):
            with pytest.raises(RecoveryRefused, match="protected_history_oversized"):
                api_server_runs._prepare_and_reserve_protected(
                    adapter,
                    owner,
                    {"session_id": "protected-nudge"},
                    admission,
                    "byf-recovery-v1:nudge",
                    "a" * 64,
                    "run_nudge",
                    {"status": "queued"},
                    deadline,
                )
        assert not any("SELECT id, role, content" in sql for sql in traced)
        assert not connection.in_transaction

        connection.set_trace_callback(None)
        db._execute_write(
            lambda conn: conn.execute(
                "DELETE FROM messages WHERE session_id=?", ("protected-nudge",)
            )
        )
        db.append_message("protected-nudge", "user", "bounded")
        expired = False
        original_decode = db._rows_to_conversation

        def expire_after_fetch(*args, **kwargs):
            nonlocal expired
            result = original_decode(*args, **kwargs)
            expired = True
            return result

        monkeypatch.setattr(db, "_rows_to_conversation", expire_after_fetch)
        monkeypatch.setattr(
            hermes_state_recovery_deadline.time,
            "monotonic",
            lambda: 10.0 if expired else 0.0,
        )
        with recovery_deadline(5.0):
            with pytest.raises(RecoveryDeadlineExceeded):
                api_server_runs._bounded_protected_history(db, "protected-nudge")
        assert not connection.in_transaction
    finally:
        connection.set_trace_callback(None)
        db.close()


def test_bounded_nudge_history_matches_existing_model_projection(
    tmp_path: Path,
) -> None:
    from gateway.platforms.api_server_runs import _bounded_protected_history
    from hermes_state_recovery_deadline import recovery_deadline

    db = SessionDB(tmp_path / "state.db")
    db.create_session("nudge", "api_server")
    db.append_message("nudge", "user", "hello")
    db.append_message("nudge", "assistant", "world")
    try:
        expected = db.get_messages_as_conversation("nudge")
        with recovery_deadline(time.monotonic() + 5):
            actual = _bounded_protected_history(db, "nudge")
        assert actual == expected
        assert len(actual) == 2
        connection = db._conn
        assert connection is not None and not connection.in_transaction
    finally:
        db.close()


@pytest.mark.asyncio
async def test_late_committed_reserve_dispatches_after_http_timeout_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import (
        api_server,
        api_server_recovery_runtime,
        api_server_runs,
    )
    import hermes_state_recovery_provider

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    monkeypatch.setattr(api_server, "_PROTECTED_ADMISSION_SECONDS", 1.0)
    selected = type("Selected", (), {})()
    captures = 0

    def prepare(owner, *, session_id):
        return SimpleNamespace(
            profile=owner.profile,
            home=owner.home,
            scope_digest=owner.scope_digest,
            session_id=session_id,
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        )

    def capture(session_id, *, deadline):
        nonlocal captures
        captures += 1
        return SelectedProviderCapture(provider_admission(session_id), selected)

    async def no_external_run(adapter, run, *, _api_server):
        run.recovery_execution_settled.set()
        run.recovery_registry.request_close()
        run.recovery_coroutine_settled.set()
        api_server_runs._retire_live_run(adapter, run.run_id)

    committed = threading.Event()
    release = threading.Event()
    reserve = RecoveryStore.reserve

    def delayed_reserve(store, *args, **kwargs):
        result = reserve(store, *args, **kwargs)
        committed.set()
        assert release.wait(timeout=3), "test did not release committed reserve"
        return result

    monkeypatch.setattr(
        api_server_recovery_runtime, "prepare_static_chat_runtime", prepare
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider, "capture_selected_provider_admission", capture
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    monkeypatch.setattr(RecoveryStore, "reserve", delayed_reserve)
    monkeypatch.setattr(api_server_runs, "_execute_run", no_external_run)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "late-protected",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": "byf-recovery-v1:late-commit",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            request = asyncio.create_task(
                client.post("/v1/runs", json=body, headers=headers)
            )
            assert await asyncio.to_thread(committed.wait, 0.8)
            timed_out = await request
            assert timed_out.status == 504
            assert adapter._pending_agent_requests == 1
            release.set()

            async def settled() -> None:
                while adapter._pending_agent_requests:
                    await asyncio.sleep(0.001)

            await asyncio.wait_for(settled(), timeout=1)
            replay = await client.post("/v1/runs", json=body, headers=headers)
            assert replay.status == 202, await replay.text()
            assert (await replay.json())["replayed"] is True
            assert captures == 1
    finally:
        release.set()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_two_stalled_precommit_workers_retain_slots_and_refuse_third(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server, api_server_recovery_runtime
    import hermes_state_recovery_provider

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    monkeypatch.setattr(api_server, "_PROTECTED_ADMISSION_SECONDS", 0.4)
    entered = threading.Event()
    release = threading.Event()
    count_lock = threading.Lock()
    count = 0

    def stalled_prepare(owner, *, session_id):
        nonlocal count
        with count_lock:
            count += 1
            if count == 2:
                entered.set()
        assert release.wait(timeout=3), "test did not release preparation"
        return SimpleNamespace(
            profile=owner.profile,
            home=owner.home,
            scope_digest=owner.scope_digest,
            session_id=session_id,
            model="gpt-4.1",
            provider="openai-api",
        )

    monkeypatch.setattr(
        api_server_recovery_runtime, "prepare_static_chat_runtime", stalled_prepare
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda *_args, **_kwargs: pytest.fail("expired prep reached provider capture"),
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "precommit-protected",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }

    def headers(key: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {_KEY}",
            "Idempotency-Key": f"byf-recovery-v1:{key}",
        }

    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            first = asyncio.create_task(
                client.post("/v1/runs", json=body, headers=headers("one"))
            )
            second = asyncio.create_task(
                client.post("/v1/runs", json=body, headers=headers("two"))
            )
            assert await asyncio.to_thread(entered.wait, 0.25)
            third = await client.post("/v1/runs", json=body, headers=headers("three"))
            assert third.status == 429
            assert (await first).status == 504
            assert (await second).status == 504
            assert adapter._pending_agent_requests == 2
            assert len(adapter._recovery_workers._futures) == 2
            release.set()

            async def settled() -> None:
                while adapter._pending_agent_requests:
                    await asyncio.sleep(0.001)

            await asyncio.wait_for(settled(), timeout=1)
            assert not (home / "state.db").exists()
    finally:
        release.set()
        await adapter.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["provider_after_commit", "dispatch_submission"])
async def test_committed_but_undispatched_member_is_explicitly_incomplete(
    fault: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime, api_server_runs
    import hermes_state_recovery_provider
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    selected = type("Selected", (), {})()

    def prepare(owner, *, session_id):
        return SimpleNamespace(
            profile=owner.profile,
            home=owner.home,
            scope_digest=owner.scope_digest,
            session_id=session_id,
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        )

    def capture(session_id, *, deadline):
        return SelectedProviderCapture(provider_admission(session_id), selected)

    checks = 0

    def require_selected(_capture):
        nonlocal checks
        checks += 1
        if fault == "provider_after_commit" and checks == 2:
            raise RecoveryRefused("provider_selection_changed")
        return selected

    monkeypatch.setattr(
        api_server_recovery_runtime, "prepare_static_chat_runtime", prepare
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider, "capture_selected_provider_admission", capture
    )
    monkeypatch.setattr(SelectedProviderCapture, "require_selected", require_selected)
    if fault == "dispatch_submission":
        create_task = asyncio.create_task

        def reject_run_task(coroutine, *args, **kwargs):
            if (
                getattr(getattr(coroutine, "cr_code", None), "co_name", "")
                == "_execute_run"
            ):
                raise RuntimeError("scratch dispatch failure")
            return create_task(coroutine, *args, **kwargs)

        monkeypatch.setattr(api_server_runs.asyncio, "create_task", reject_run_task)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "undispatched-protected",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": f"byf-recovery-v1:{fault}",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post("/v1/runs", json=body, headers=headers)
            assert response.status == 503, await response.text()
            db = adapter._session_dbs[str(home)]
            row = db._read_one(
                "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
                (body["session_id"],),
            )
            assert row is not None
            expected = (
                "unsupported_configuration"
                if fault == "provider_after_commit"
                else "unclosed_producer"
            )
            assert expected in json.loads(row[0])
            member = db._read_one(
                "SELECT producer_state FROM recovery_members WHERE session_id=?",
                (body["session_id"],),
            )
            assert member is not None and member[0] == "incomplete"
            assert not getattr(adapter, "_active_run_tasks")
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_postreserve_registration_does_not_block_unrelated_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime, api_server_runs
    import hermes_state_recovery_provider

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    selected = type("Selected", (), {})()

    def prepare(owner, *, session_id):
        return SimpleNamespace(
            profile=owner.profile,
            home=owner.home,
            scope_digest=owner.scope_digest,
            session_id=session_id,
            model="gpt-4.1",
            provider="openai-api",
            selected_provider=selected,
        )

    monkeypatch.setattr(
        api_server_recovery_runtime, "prepare_static_chat_runtime", prepare
    )
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda session_id, *, deadline: SelectedProviderCapture(
            provider_admission(session_id), selected
        ),
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )

    async def no_external_run(adapter, run, *, _api_server):
        run.recovery_execution_settled.set()
        run.recovery_registry.request_close()
        run.recovery_coroutine_settled.set()
        api_server_runs._retire_live_run(adapter, run.run_id)

    monkeypatch.setattr(api_server_runs, "_execute_run", no_external_run)
    entered = threading.Event()
    release = threading.Event()
    register = RecoveryStore.register_producer

    def held_register(store, *args, **kwargs):
        result = register(store, *args, **kwargs)
        entered.set()
        assert release.wait(timeout=2), "test did not release registered producer"
        return result

    monkeypatch.setattr(RecoveryStore, "register_producer", held_register)

    def watchdog() -> None:
        if entered.wait(timeout=2):
            release.wait(timeout=0.3)
            release.set()

    safety = threading.Thread(target=watchdog)
    safety.start()
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "held-registration",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    headers = {
        "Authorization": f"Bearer {_KEY}",
        "Idempotency-Key": "byf-recovery-v1:held-registration",
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            request = asyncio.create_task(
                client.post("/v1/runs", json=body, headers=headers)
            )
            assert await asyncio.to_thread(entered.wait, 1)
            assert not release.is_set(), (
                "registration blocked the event loop until watchdog release"
            )
            probe = await asyncio.wait_for(
                client.get("/scratch-loop-probe"), timeout=0.1
            )
            assert probe.status == 200
            release.set()
            assert (await request).status == 202
    finally:
        release.set()
        safety.join(timeout=1)
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_cold_protected_status_uses_two_real_workers_and_retains_timeout_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.platforms import api_server_recovery, api_server_runs

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(api_server_runs, "_COLD_PROTECTED_STATUS_SECONDS", 0.15)
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    count = 0
    worker_threads: set[int] = set()
    loop_thread = threading.get_ident()

    def held_read(_owner, _run_id):
        nonlocal count
        with lock:
            count += 1
            worker_threads.add(threading.get_ident())
            if count == 2:
                entered.set()
        assert release.wait(timeout=2), "test did not release cold status"
        return None

    monkeypatch.setattr(api_server_recovery, "read_protected_run_status", held_read)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    headers = {"Authorization": f"Bearer {_KEY}"}
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            first = asyncio.create_task(
                client.get("/v1/runs/run_coldone", headers=headers)
            )
            second = asyncio.create_task(
                client.get("/v1/runs/run_coldtwo", headers=headers)
            )
            assert await asyncio.to_thread(entered.wait, 0.1)
            third = await client.get("/v1/runs/run_coldthree", headers=headers)
            assert third.status == 429
            assert (await first).status == 504
            assert (await second).status == 504
            assert len(adapter._recovery_workers._futures) == 2
            assert len(worker_threads) == 2 and loop_thread not in worker_threads
            release.set()
    finally:
        release.set()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_served_protected_worker_sends_and_accounts_with_real_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import run_agent  # the gateway's completed turn-machinery warm-up
    from openai import OpenAI
    from openai._base_client import SyncHttpxClientWrapper
    from openai.resources.chat.completions import Completions
    from openai.types.chat import ChatCompletionChunk
    from openai.types.chat.chat_completion_chunk import Choice, ChoiceDelta
    from openai.types.completion_usage import CompletionUsage
    from httpx import HTTPTransport
    import hermes_state_recovery_provider
    from tests.agent.test_recovery_runtime import (
        _admitted,
        _install_selected_plugin_fixture,
    )
    from tests.gateway.test_api_server_recovery_runtime import _profile

    profile = _profile(tmp_path, monkeypatch)
    db, _store, _scope, registry = _admitted(profile.home)
    _install_selected_plugin_fixture(registry, monkeypatch)
    selected = registry.provider_capture.provider
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda session_id, *, deadline: SelectedProviderCapture(
            provider_admission(session_id), selected
        ),
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    sends: list[tuple[OpenAI, dict]] = []

    def fake_sdk_create(self, **kwargs):
        assert isinstance(self._client, OpenAI)
        sends.append((self._client, kwargs))
        assert kwargs["model"] == "gpt-4.1"
        assert kwargs["stream"] is True
        return iter([
            ChatCompletionChunk(
                id="chatcmpl-scratch",
                created=1730000000,
                model="gpt-4.1",
                object="chat.completion.chunk",
                choices=[
                    Choice(
                        index=0,
                        delta=ChoiceDelta(content="done"),
                        finish_reason="stop",
                    )
                ],
            ),
            ChatCompletionChunk(
                id="chatcmpl-scratch",
                created=1730000000,
                model="gpt-4.1",
                object="chat.completion.chunk",
                choices=[],
                usage=CompletionUsage(
                    prompt_tokens=2, completion_tokens=3, total_tokens=5
                ),
            ),
        ])

    monkeypatch.setattr(Completions, "create", fake_sdk_create)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "served-protected",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json=body,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:real-constructor",
                },
            )
            assert response.status == 202, await response.text()
            run_id = (await response.json())["run_id"]
            for _ in range(100):
                status = getattr(adapter, "_run_statuses").get(run_id, {})
                if status.get("status") in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(0.02)
            assert status.get("status") == "completed", status
            assert len(sends) == 1
            assert status["output"] == "done"
            assert type(sends[0][0]._client) is SyncHttpxClientWrapper
            assert type(sends[0][0]._client._transport) is HTTPTransport
            member_scope = db._read_one(
                "SELECT profile,scope_digest FROM recovery_members WHERE run_id=?",
                (run_id,),
            )
            assert member_scope is not None
            served_scope = RecoveryScope(
                _store.store_id, member_scope[0], member_scope[1], body["session_id"]
            )
            sends_inventory = _store.send_inventory(served_scope, run_id)
            assert len(sends_inventory) == 1
            assert sends_inventory[0][2] == "accounted"
            for _ in range(100):
                producer_state = db._read_one(
                    "SELECT producer_state FROM recovery_members WHERE run_id=?",
                    (run_id,),
                )[0]
                if producer_state == "closed":
                    break
                await asyncio.sleep(0.02)
            assert producer_state == "closed"
            assert (
                db._read_retrying_ioerr(
                    lambda conn: conn.execute(
                        "SELECT state FROM recovery_usage_slots WHERE delta_id=?",
                        (sends_inventory[0][3],),
                    ).fetchone()
                )[0]
                == "committed"
            )
            assert tuple(
                db._read_one(
                    "SELECT api_call_count,input_tokens,output_tokens FROM sessions WHERE id=?",
                    (body["session_id"],),
                )
            ) == (1, 2, 3)
            transcript = [
                tuple(row)
                for row in db._read_all(
                    "SELECT role,content FROM messages WHERE session_id=? ORDER BY id",
                    (body["session_id"],),
                )
            ]
            assert ("user", "work") in transcript
            assert ("assistant", "done") in transcript
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_served_protected_worker_constructs_real_agent_without_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import run_agent  # completed gateway turn-machinery warm-up
    from gateway.platforms import api_server_runs
    import hermes_state_recovery_provider
    from tests.agent.test_recovery_runtime import (
        _admitted,
        _install_selected_plugin_fixture,
    )
    from tests.gateway.test_api_server_recovery_runtime import _profile

    profile = _profile(tmp_path, monkeypatch)
    db, _store, _scope, registry = _admitted(profile.home)
    _install_selected_plugin_fixture(registry, monkeypatch)
    selected = registry.provider_capture.provider
    monkeypatch.setattr(
        hermes_state_recovery_provider,
        "capture_selected_provider_admission",
        lambda session_id, *, deadline: SelectedProviderCapture(
            provider_admission(session_id),
            selected,
        ),
    )
    monkeypatch.setattr(
        SelectedProviderCapture, "require_selected", lambda self: selected
    )
    constructed: list[str] = []

    def no_model_call(_adapter, _run, agent, _approval_notify, *, _api_server):
        constructed.append(agent.model)
        return {"final_response": "local-only"}, {"input_tokens": 0}

    monkeypatch.setattr(api_server_runs, "_run_agent_sync_body", no_model_call)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))
    body = {
        "input": "work",
        "session_id": "served-no-call",
        "model": "gpt-4.1",
        "provider": "openai-api",
        "recovery": {
            "schema": "hermes.recovery/v1",
            "generation": 0,
            "parent_run_id": None,
        },
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs",
                json=body,
                headers={
                    "Authorization": f"Bearer {_KEY}",
                    "Idempotency-Key": "byf-recovery-v1:real-no-call",
                },
            )
            assert response.status == 202, await response.text()
            run_id = (await response.json())["run_id"]
            for _ in range(100):
                status = getattr(adapter, "_run_statuses").get(run_id, {})
                producer = db._read_one(
                    "SELECT producer_state FROM recovery_members WHERE run_id=?",
                    (run_id,),
                )
                if (
                    status.get("status") == "completed"
                    and producer is not None
                    and producer[0] == "closed"
                ):
                    break
                await asyncio.sleep(0.02)
            assert status.get("status") == "completed"
            assert constructed == ["gpt-4.1"]
            assert producer is not None and producer[0] == "closed"
            assert (
                db._read_one(
                    "SELECT COUNT(*) FROM recovery_sends WHERE run_id=?", (run_id,)
                )[0]
                == 0
            )
            assert (
                db._read_one(
                    "SELECT COUNT(*) FROM sessions WHERE id=?", (body["session_id"],)
                )[0]
                == 1
            )
    finally:
        await adapter.disconnect()
        db.close()
