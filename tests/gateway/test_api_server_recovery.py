"""Owner-only recovery HTTP routes keep immutable reads and workers bounded."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
import weakref
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import GatewayConfig, PlatformConfig
from gateway.platforms.api_server import APIServerAdapter, _api_request_profile
from gateway.platforms import api_server_recovery as recovery
from gateway.platforms.api_server_recovery_artifacts import canonical_json_bytes
from gateway.platforms.api_server_recovery_contract import (
    RecoveryAdmission,
    SealRequest,
    SignedStatusWire,
)
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
    membership_sha256,
)
from hermes_state_recovery_provider import SelectedProviderCapture
from hermes_state_recovery_seal import (
    finalize,
    prepare_provider_evidence,
    read_seal_bytes,
    read_sealed_page_bytes,
)
from agent.recovery_context import (
    AdmissionHandoff,
    current_incarnation,
    issue_producer_permit,
)
from tests.recovery_provider_fixture import provider_admission, selected_provider


_KEY = "scratch-owner-key-at-least-sixteen"


def _adapter() -> APIServerAdapter:
    return APIServerAdapter(PlatformConfig(enabled=True, extra={"key": _KEY}))


def _app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application(middlewares=[adapter._make_profile_prefix_middleware()])
    for method, path, handler in recovery.http_routes(adapter):
        app.router.add_route(method, path, handler)
        app.router.add_route(method, f"/p/{{profile}}{path}", handler)
    return app


def _request(*values: str) -> web.Request:
    class Headers(dict):
        def getall(self, name, default):
            return list(values) if name == "Authorization" else default

    return cast(
        web.Request,
        SimpleNamespace(headers=Headers(Authorization=values[0] if values else "")),
    )


def _no_call_case(
    home: Path,
    owner: recovery.RecoveryOwnerContext,
    monkeypatch,
    *,
    seal_now: bool = True,
    close_producer: bool = True,
):
    db = SessionDB(home / "state.db")
    store = RecoveryStore(db)
    root = "run_root"
    session_id = "http-recovery-session"
    scope = RecoveryScope(store.store_id, owner.profile, owner.scope_digest, session_id)
    admission = provider_admission(session_id)
    plugin = selected_provider(monkeypatch, session_id=session_id)
    reserved = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope,
            "byf-recovery-v1:http-root",
            "a" * 64,
            root,
            current_incarnation(),
            admission,
        ),
    )
    assert reserved.outcome == "created"
    row = db._read_one("SELECT source FROM sessions WHERE id=?", (session_id,))
    assert row is not None and row[0] == "api_server"
    assert isinstance(reserved.handoff, AdmissionHandoff)
    producer = issue_producer_permit(store, reserved.handoff)
    store.register_producer(scope, root, producer, "status-barrier", "callback")
    store.start_registered_producer(scope, root, producer, "status-barrier")
    store.update_status(root, {"status": "completed"})
    store.close_registered_producer(scope, root, producer, "status-barrier")
    if close_producer:
        store.close_producer(scope, root, producer)
    request = SealRequest(
        request_id=str(uuid4()),
        session_id=session_id,
        run_ids=(root,),
        expected_membership_sha256=membership_sha256((root,)),
    )
    signed = SignedStatusWire.model_validate({
        "schema": "byf.signed-workspace-status/v1",
        "status": {
            "schema": "byf.workspace-status/v1",
            "reference": admission.reference.model_dump(mode="json"),
            "session_id": session_id,
            "epoch_id": "epoch-1",
            "revision": 1,
            "previous_state": None,
            "state": "active",
            "valid_until": "2099-01-01T00:00:00Z",
            "maximum_expires_at": "2099-01-01T00:00:00Z",
        },
        "key_id": "scratch",
        "hmac_sha256": "c" * 64,
    })

    class RecoveryProviderReadback:
        def __init__(self):
            self.admission = admission
            self.state = "unused"
            self.signed_status = signed
            self.signed_status_sha256 = hashlib.sha256(
                canonical_json_bytes(signed)
            ).hexdigest()
            self.status_state = "active"
            self.status_revision = 1
            self.container_id = None
            self.container_attestation_sha256 = None

    RecoveryProviderReadback.__module__ = "byf_workspace.workspace_recovery"
    read_deadlines: list[float | None] = []

    def readback(expected: bytes, *, deadline: float | None = None):
        assert expected == admission.canonical_bytes()
        assert store.lookup_root(scope, root).phase == "closing"
        read_deadlines.append(deadline)
        return RecoveryProviderReadback()

    plugin.read_recovery_binding_wire = readback
    if seal_now:
        assert close_producer
        assert store.begin_close(scope, request).phase == "closing"
        evidence = prepare_provider_evidence(SelectedProviderCapture(admission, plugin))
        assert finalize(store, scope, request, evidence).state == "sealed"
    return db, store, scope, request, plugin, read_deadlines


def test_owner_context_uses_physical_base_profile_and_existing_digest(
    tmp_path, monkeypatch
) -> None:
    default_home = tmp_path / ".hermes"
    named_home = default_home / "profiles" / "byf-builder"
    named_home.mkdir(parents=True)
    monkeypatch.setattr(
        "hermes_cli.profiles._get_default_hermes_home", lambda: default_home
    )
    monkeypatch.setenv("HERMES_HOME", str(named_home))
    adapter = _adapter()
    request = _request(f"Bearer {_KEY}")
    owner = recovery.capture_owner_context(adapter, request, selected_profile=None)
    assert owner.profile == "byf-builder"
    assert owner.home == named_home
    expected = hashlib.sha256(f"default\0{_KEY}".encode()).hexdigest()
    assert owner.scope_digest == expected
    assert owner.scope_digest == adapter._run_idempotency_scope(request)


def test_owner_context_rejects_no_key_and_room_grant_beside_bearer(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    adapter = _adapter()
    adapter._api_key = ""
    with pytest.raises(recovery.RecoveryHttpRefused) as no_key:
        recovery.capture_owner_context(
            adapter, _request("Bearer anything"), selected_profile=None
        )
    assert no_key.value.status == 401
    adapter._api_key = _KEY
    with pytest.raises(recovery.RecoveryHttpRefused) as room:
        recovery.capture_owner_context(
            adapter,
            _request(f"Bearer {_KEY}", "HermesRoom grant"),
            selected_profile=None,
        )
    assert room.value.status == 401
    monkeypatch.setattr(
        adapter, "_room_grant_token", lambda request: "alternate-room-grant"
    )
    with pytest.raises(recovery.RecoveryHttpRefused) as alternate:
        recovery.capture_owner_context(
            adapter, _request(f"Bearer {_KEY}"), selected_profile=None
        )
    assert alternate.value.status == 401


def test_readonly_root_lookup_ignores_foreign_override_and_does_not_create(
    tmp_path,
) -> None:
    adapter = _adapter()
    foreign_home = tmp_path / "foreign"
    foreign_home.mkdir()
    selected_home = tmp_path / "selected"
    selected_home.mkdir()
    db = SessionDB(foreign_home / "state.db")
    adapter._session_db = db
    try:
        owner = recovery.RecoveryOwnerContext("selected", selected_home, "a" * 64)
        with pytest.raises(recovery.RecoveryHttpRefused) as refused:
            with recovery._read_scope_for_root(owner, "run_root"):
                pytest.fail("absent root opened")
        assert refused.value.status == 404
        assert not (selected_home / "state.db").exists()
    finally:
        db.close()


@pytest.mark.asyncio
async def test_served_capability_requires_explicit_yaml_and_owner(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    adapter = _adapter()
    config = tmp_path / "config.yaml"
    app = _app(adapter)
    try:
        async with TestClient(TestServer(app)) as client:
            disabled = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            assert disabled.status == 404
            config.write_text(
                "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
            )
            missing = await client.get("/v1/recovery/capabilities")
            assert missing.status == 401
            ready = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            assert ready.status == 200
            wire = await ready.json()
            assert wire["schema"] == "hermes.recovery-capabilities/v1"
            assert wire["enabled"] is True and wire["ready"] is False
            assert wire["limits"]["max_workers"] == 2
            config.write_text(
                "platforms:\n  api_server:\n    recovery:\n      enabled: yes-ish\n"
            )
            invalid = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            assert invalid.status == 404
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_capability_source_only_read_uses_selected_owner_and_worker_deadline(
    tmp_path, monkeypatch
) -> None:
    from gateway.platforms import api_server_recovery_runtime

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    loop_thread = threading.get_ident()
    observed = []

    def source_only(owner, *, deadline):
        observed.append((owner.home, deadline, threading.get_ident()))
        return True

    monkeypatch.setattr(api_server_recovery_runtime, "static_runtime_ready", source_only)
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            assert response.status == 200
            assert (await response.json())["ready"] is True
        assert len(observed) == 1
        assert observed[0][0] == tmp_path
        assert observed[0][1] > time.monotonic()
        assert observed[0][2] != loop_thread
        assert not (tmp_path / "state.db").exists()
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_named_base_multiplex_default_mirror_uses_default_profile_key(
    tmp_path, monkeypatch
) -> None:
    from agent import secret_scope

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    root = tmp_path / ".hermes"
    named = root / "profiles" / "byf-builder"
    named.mkdir(parents=True)
    default_key = "default-profile-scratch-key-123456"
    named_key = "named-profile-scratch-key-123456"
    (root / ".env").write_text(f"API_SERVER_KEY={default_key}\n")
    (named / ".env").write_text(f"API_SERVER_KEY={named_key}\n")
    for home in (root, named):
        (home / "config.yaml").write_text(
            "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
        )
    monkeypatch.setenv("HERMES_HOME", str(named))
    monkeypatch.setattr(
        "hermes_cli.profiles.profiles_to_serve",
        lambda multiplex: [("default", root), ("byf-builder", named)],
    )
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": named_key}))
    adapter.gateway_runner = SimpleNamespace(
        config=GatewayConfig(multiplex_profiles=True)
    )
    secret_scope.set_multiplex_active(True)
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            default = await client.get(
                "/p/default/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {default_key}"},
            )
            assert default.status == 200
            wrong_default = await client.get(
                "/p/default/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {named_key}"},
            )
            assert wrong_default.status == 401
            named_response = await client.get(
                "/p/byf-builder/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {named_key}"},
            )
            assert named_response.status == 200
            wrong_named = await client.get(
                "/p/byf-builder/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {default_key}"},
            )
            assert wrong_named.status == 401
            unprefixed = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {named_key}"},
            )
            assert unprefixed.status == 200
            wrong_base = await client.get(
                "/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {default_key}"},
            )
            assert wrong_base.status == 401
            for selected, key, expected_home in (
                ("default", default_key, root),
                ("byf-builder", named_key, named),
            ):
                token = _api_request_profile.set(selected)
                try:
                    with adapter._profile_scope(selected):
                        request = _request(f"Bearer {key}")
                        owner = recovery.capture_owner_context(
                            adapter, request, selected_profile=selected
                        )
                        assert owner.profile == selected
                        assert owner.home == expected_home
                        assert owner.scope_digest == adapter._run_idempotency_scope(
                            request
                        )
                finally:
                    _api_request_profile.reset(token)
            (root / ".env").unlink()
            no_default_key = await client.get(
                "/p/default/v1/recovery/capabilities",
                headers={"Authorization": f"Bearer {named_key}"},
            )
            assert no_default_key.status == 401
    finally:
        secret_scope.set_multiplex_active(False)
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_served_routes_reject_unbounded_or_ambiguous_inputs_before_db(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    headers = {"Authorization": f"Bearer {_KEY}"}
    valid = {
        "request_id": str(uuid4()),
        "session_id": "session",
        "run_ids": ["other-root"],
        "expected_membership_sha256": "a" * 64,
    }
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            missing = await client.get(
                "/v1/runs/root/sealed-transcript", headers=headers
            )
            assert missing.status == 404
            for query in ("page=-1", "page=01", "page=0&x=1", "page=0&page=1"):
                invalid = await client.get(
                    f"/v1/runs/root/sealed-transcript?{query}", headers=headers
                )
                assert invalid.status == 400
            huge_page = await client.get(
                "/v1/runs/root/sealed-transcript?page=" + "9" * 5000,
                headers=headers,
            )
            assert huge_page.status in {400, 404}
            extra_capability = await client.get(
                "/v1/recovery/capabilities?x=1", headers=headers
            )
            assert extra_capability.status == 400
            extra_post = await client.post(
                "/v1/runs/root/seal?x=1", data=b"{}", headers=headers
            )
            assert extra_post.status == 400
            oversized = await client.post(
                "/v1/runs/root/seal", data=b" " * 16_385, headers=headers
            )
            assert oversized.status == 413
            duplicate = await client.post(
                "/v1/runs/root/seal", data=b'{"x":1,"x":2}', headers=headers
            )
            assert duplicate.status == 400
            nonfinite = await client.post(
                "/v1/runs/root/seal", data=b'{"x":NaN}', headers=headers
            )
            assert nonfinite.status == 400
            mismatch = await client.post(
                "/v1/runs/root/seal", data=json.dumps(valid), headers=headers
            )
            assert mismatch.status == 400
    finally:
        await adapter.disconnect()
    assert not (tmp_path / "state.db").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("ordinary_file", [False, True])
async def test_cold_missing_root_reads_never_initialize_or_reconcile_store(
    tmp_path, monkeypatch, ordinary_file: bool
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    state_path = home / "state.db"
    if ordinary_file:
        ordinary = SessionDB(state_path)
        ordinary.close()
    before = state_path.read_bytes() if ordinary_file else None
    adapter = _adapter()
    request = SealRequest(
        request_id=str(uuid4()),
        session_id="missing-session",
        run_ids=("missing-root",),
        expected_membership_sha256=membership_sha256(("missing-root",)),
    )
    headers = {"Authorization": f"Bearer {_KEY}"}
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            for method, path, data in (
                ("GET", "/v1/runs/missing-root/seal", None),
                ("GET", "/v1/runs/missing-root/sealed-transcript?page=0", None),
                (
                    "POST",
                    "/v1/runs/missing-root/seal",
                    request.model_dump_json(by_alias=True),
                ),
            ):
                response = await client.request(
                    method, path, data=data, headers=headers
                )
                assert response.status == 404, await response.text()
        assert (state_path.read_bytes() if state_path.exists() else None) == before
        assert not list(home.glob("state.db.malformed-backup-*"))
        assert not list(home.glob("state.db.repair-scratch*"))
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_served_get_replays_exact_committed_bytes_after_reopen(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    assert owner.profile == "default"
    db, store, scope, seal_request, _, _ = _no_call_case(home, owner, monkeypatch)
    saved_result = read_seal_bytes(store, scope, "run_root")
    saved_page = read_sealed_page_bytes(store, scope, "run_root", 0)
    with recovery._read_scope_for_root(owner, "run_root") as (read_view, read_scope, _):
        assert read_scope == scope and not hasattr(read_view, "_write")
        assert read_view.db._conn.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            read_view.db._conn.execute(
                "UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
                (scope.session_id,),
            )
    adapter._session_db = db
    headers = {"Authorization": f"Bearer {_KEY}"}
    from gateway.platforms import api_server_runs as runs

    monkeypatch.setattr(
        runs,
        "_selected_provider_capture_for_scope",
        lambda *args: pytest.fail("GET selected provider"),
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            result = await client.get("/v1/runs/run_root/seal", headers=headers)
            assert result.status == 200 and await result.read() == saved_result
            page = await client.get(
                "/v1/runs/run_root/sealed-transcript?page=0", headers=headers
            )
            assert page.status == 200 and await page.read() == saved_page
            absent = await client.get("/v1/runs/other/seal", headers=headers)
            assert absent.status == 404
    finally:
        await adapter.disconnect()
        db.close()

    reopened = _adapter()
    try:
        async with TestClient(TestServer(_app(reopened))) as client:
            result = await client.get("/v1/runs/run_root/seal", headers=headers)
            assert result.status == 200 and await result.read() == saved_result
            page = await client.get(
                "/v1/runs/run_root/sealed-transcript?page=0", headers=headers
            )
            assert page.status == 200 and await page.read() == saved_page
            replay = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert replay.status == 200 and await replay.read() == saved_result
    finally:
        await reopened.disconnect()


@pytest.mark.asyncio
async def test_committed_post_retry_is_byte_identical_without_provider(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    db, store, scope, seal_request, _, _ = _no_call_case(home, owner, monkeypatch)
    saved = read_seal_bytes(store, scope, "run_root")
    adapter._session_db = db
    headers = {"Authorization": f"Bearer {_KEY}"}
    from gateway.platforms import api_server_runs as runs

    monkeypatch.setattr(
        runs,
        "_selected_provider_capture_for_scope",
        lambda *args: pytest.fail("committed retry selected provider"),
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            replay = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert replay.status == 200 and await replay.read() == saved
            changed = seal_request.model_copy(update={"request_id": str(uuid4())})
            mismatch = await client.post(
                "/v1/runs/run_root/seal",
                data=changed.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert mismatch.status == 409
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_post_seals_after_durable_close_with_selected_readback_deadline(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    db, store, scope, seal_request, plugin, read_deadlines = _no_call_case(
        home, owner, monkeypatch, seal_now=False
    )
    adapter._session_db = db
    admission = provider_admission(scope.session_id)
    identities = cast(
        dict[RecoveryScope, tuple[weakref.ReferenceType[object], bytes]],
        getattr(adapter, "_protected_provider_identities"),
    )
    identities[scope] = (
        weakref.ref(plugin),
        admission.canonical_bytes(),
    )
    headers = {"Authorization": f"Bearer {_KEY}"}
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert response.status == 200, await response.text()
            saved = await response.read()
            assert saved == read_seal_bytes(store, scope, "run_root")
            assert read_deadlines and read_deadlines[0] is not None
            assert identities.get(scope) is None
            again = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert again.status == 200 and await again.read() == saved
            assert len(read_deadlines) == 1
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_committed_post_replay_retires_identity_after_lost_response_readback(
    tmp_path, monkeypatch
) -> None:
    import hermes_state_recovery_seal as sealer

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    db, store, scope, seal_request, plugin, read_deadlines = _no_call_case(
        home, owner, monkeypatch, seal_now=False
    )
    adapter._session_db = db
    admission = provider_admission(scope.session_id)
    identities = cast(
        dict[RecoveryScope, tuple[weakref.ReferenceType[object], bytes]],
        getattr(adapter, "_protected_provider_identities"),
    )
    identities[scope] = (weakref.ref(plugin), admission.canonical_bytes())
    original = sealer.read_committed_seal_bytes
    calls = 0

    def lose_second_read(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RecoveryRefused("seal_deadline_exceeded")
        return original(*args, **kwargs)

    monkeypatch.setattr(sealer, "read_committed_seal_bytes", lose_second_read)
    headers = {"Authorization": f"Bearer {_KEY}"}
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            first = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert first.status == 504
            assert read_deadlines and identities.get(scope) is None
            saved = read_seal_bytes(store, scope, "run_root")
            retry = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers=headers,
            )
            assert retry.status == 200 and await retry.read() == saved
            assert len(read_deadlines) == 1 and calls == 3
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("close_producer", [False, True])
async def test_post_keeps_close_barrier_for_open_producer_or_lost_identity(
    tmp_path, monkeypatch, close_producer: bool
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    db, store, scope, seal_request, _, read_deadlines = _no_call_case(
        home, owner, monkeypatch, seal_now=False, close_producer=close_producer
    )
    adapter._session_db = db
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            if close_producer:
                assert response.status == 409
                assert (await response.json())["error"]["code"] == (
                    "provider_identity_unavailable"
                )
            else:
                assert response.status == 200
                assert (await response.json())["state"] == "pending"
            assert store.lookup_root(scope, "run_root").phase == "closing"
            assert read_deadlines == []
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_new_post_needs_existing_same_process_writer(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    adapter = _adapter()
    owner = recovery.capture_owner_context(
        adapter, _request(f"Bearer {_KEY}"), selected_profile=None
    )
    db, store, scope, seal_request, _, _ = _no_call_case(
        home, owner, monkeypatch, seal_now=False
    )
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/runs/run_root/seal",
                data=seal_request.model_dump_json(by_alias=True),
                headers={"Authorization": f"Bearer {_KEY}"},
            )
            assert response.status == 503
            row = db._read_one(
                "SELECT phase,close_request_id FROM recovery_sessions WHERE session_id=?",
                (scope.session_id,),
            )
            assert row is not None and tuple(row) == ("open", None)
            assert adapter._session_dbs == {}
    finally:
        await adapter.disconnect()
        db.close()


@pytest.mark.asyncio
async def test_worker_pool_retains_slots_after_await_cancellation_and_joins() -> None:
    pool = recovery.RecoveryWorkerPool()
    entered = threading.Event()
    release = threading.Event()
    count = 0
    count_lock = threading.Lock()

    def block(deadline: float) -> bytes:
        nonlocal count
        with count_lock:
            count += 1
            if count == 2:
                entered.set()
        assert deadline > time.monotonic()
        assert release.wait(timeout=3)
        return b"ok"

    one = pool.submit(block)
    two = pool.submit(block)
    assert await asyncio.to_thread(entered.wait, 2)
    waiter = asyncio.ensure_future(asyncio.shield(asyncio.wrap_future(one.future)))
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    with pytest.raises(recovery.RecoveryHttpRefused) as third:
        pool.submit(block)
    assert third.value.status == 429
    joining = asyncio.create_task(pool.join())
    await asyncio.sleep(0)
    assert not joining.done()
    release.set()
    assert await joining is False
    assert one.future.result() == two.future.result() == b"ok"


@pytest.mark.asyncio
async def test_worker_copies_selected_profile_context() -> None:
    pool = recovery.RecoveryWorkerPool()
    token = _api_request_profile.set("worker")
    try:
        work = pool.submit(lambda deadline: (_api_request_profile.get() or "").encode())
    finally:
        _api_request_profile.reset(token)
    assert await asyncio.wrap_future(work.future) == b"worker"
    assert await pool.join() is False


@pytest.mark.asyncio
async def test_http_timeout_keeps_real_worker_slots_until_settled(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
    )
    monkeypatch.setattr(recovery, "_WORKER_SECONDS", 0.25)
    adapter = _adapter()
    entered = threading.Event()
    release = threading.Event()
    count = 0
    lock = threading.Lock()

    def stalled(_adapter, owner, root_id, page, deadline):
        nonlocal count
        from hermes_state_recovery_deadline import current_deadline

        assert current_deadline() == deadline
        with lock:
            count += 1
            if count == 2:
                entered.set()
        assert release.wait(timeout=3)
        return b"{}"

    monkeypatch.setattr(recovery, "_get_worker", stalled)
    headers = {"Authorization": f"Bearer {_KEY}"}
    try:
        async with TestClient(TestServer(_app(adapter))) as client:
            first = asyncio.create_task(
                client.get("/v1/runs/root/seal", headers=headers)
            )
            second = asyncio.create_task(
                client.get("/v1/runs/root/seal", headers=headers)
            )
            assert await asyncio.to_thread(entered.wait, 2)
            third = await client.get("/v1/runs/root/seal", headers=headers)
            assert third.status == 429
            assert (await first).status == 504
            assert (await second).status == 504
            still_busy = await client.get("/v1/runs/root/seal", headers=headers)
            assert still_busy.status == 429
            release.set()
    finally:
        release.set()
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_timed_out_worker_late_exception_is_collected(monkeypatch) -> None:
    monkeypatch.setattr(recovery, "_WORKER_SECONDS", 0.05)
    adapter = _adapter()
    entered = threading.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    reported: list[dict[str, object]] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: reported.append(context))

    def late_failure(_deadline: float) -> bytes:
        entered.set()
        assert release.wait(timeout=3)
        raise RuntimeError("late worker failure")

    try:
        response_task = asyncio.create_task(recovery._run(adapter, late_failure))
        assert await asyncio.to_thread(entered.wait, 2)
        response = await response_task
        assert response.status == 504
        release.set()
        assert await adapter._recovery_workers.join() is False
        await asyncio.sleep(0)
        assert reported == []
    finally:
        release.set()
        loop.set_exception_handler(previous)
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_cancelled_shutdown_still_joins_before_return() -> None:
    pool = recovery.RecoveryWorkerPool()
    entered = threading.Event()
    release = threading.Event()

    def blocked(deadline: float) -> bytes:
        entered.set()
        assert release.wait(timeout=3)
        return b"ok"

    work = pool.submit(blocked)
    assert await asyncio.to_thread(entered.wait, 2)
    joining = asyncio.create_task(pool.join())
    await asyncio.sleep(0)
    joining.cancel()
    await asyncio.sleep(0)
    assert not joining.done()
    release.set()
    assert await joining is True
    assert work.future.result() == b"ok"
