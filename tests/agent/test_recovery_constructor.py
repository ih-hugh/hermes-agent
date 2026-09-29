"""Protected constructor consumes one frozen, already loaded static route."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
import pickle
from dataclasses import replace

import pytest

from agent.recovery_context import bind_write_permit, issue_write_permit
from agent.recovery_producers import (
    SendOutcome,
    begin_chat_send,
    bind_protected_constructor,
)
from gateway.platforms.api_server_recovery_runtime import prepare_static_chat_runtime
from hermes_state_recovery import RecoveryRefused
from run_agent import AIAgent
from tests.agent.test_recovery_runtime import (
    _admitted,
    _install_selected_plugin_fixture,
)
from tests.gateway.test_api_server_recovery_runtime import _profile


def _prepared(tmp_path: Path, monkeypatch):
    owner = _profile(tmp_path, monkeypatch)
    db, store, scope, registry = _admitted(owner.home)
    manager, _ = _install_selected_plugin_fixture(registry, monkeypatch)
    prepared = prepare_static_chat_runtime(owner, session_id=scope.session_id)
    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation
    )
    executor = registry.enter(registry.permit, "executor")
    return owner, db, scope, registry, manager, prepared, writer, executor


def test_real_protected_agent_uses_loaded_terminal_without_discovery_or_checker(
    tmp_path: Path, monkeypatch
) -> None:
    from hermes_cli import plugins
    from agent import agent_runtime_helpers
    from tools import terminal_tool
    import providers

    _, db, scope, registry, manager, prepared, writer, executor = _prepared(
        tmp_path, monkeypatch
    )
    monkeypatch.setenv("OPENAI_ORG_ID", "ambient-org")
    monkeypatch.setenv("OPENAI_PROJECT_ID", "ambient-project")
    monkeypatch.setenv("OPENAI_WEBHOOK_SECRET", "ambient-webhook")
    calls: list[str] = []
    monkeypatch.setattr(plugins, "discover_plugins", lambda: calls.append("discover"))
    monkeypatch.setattr(
        terminal_tool,
        "check_terminal_requirements",
        lambda: calls.append("checker") or True,
    )

    monkeypatch.setattr(
        providers,
        "get_provider_profile",
        lambda *_: calls.append("provider_profile") or None,
    )
    monkeypatch.setattr(
        agent_runtime_helpers,
        "_provider_supplied_client",
        lambda *_a, **_k: calls.append("provider_client") or None,
    )
    monkeypatch.setattr(
        AIAgent,
        "_build_keepalive_http_client",
        lambda *_a, **_k: calls.append("keepalive") or None,
    )

    def construct() -> None:
        with bind_write_permit(writer), bind_protected_constructor(prepared):
            agent = AIAgent(
                api_key=prepared.api_key,
                base_url=prepared.base_url,
                provider=prepared.provider,
                api_mode=prepared.api_mode,
                model=prepared.model,
                enabled_toolsets=["terminal_only"],
                session_id=scope.session_id,
                session_db=db,
                platform="api_server",
                quiet_mode=True,
                skip_memory=True,
                skip_background_review=True,
                skip_context_files=True,
            )
        assert agent.valid_tool_names == {"terminal"}
        assert agent.tools == [
            {"type": "function", "function": terminal_tool.TERMINAL_SCHEMA}
        ]
        assert agent.client.organization == ""
        assert agent.client.project == ""
        assert agent.client.webhook_secret == ""
        sdk = registry.enter(registry.permit, "sdk")

        def qualify_client() -> None:
            send = begin_chat_send(agent.client)
            assert send is not None
            send.finish(
                SendOutcome(
                    kind="no_charge_proved",
                    attempt_id=send.attempt_id,
                    reason="sdk_not_entered",
                )
            )

        sdk.run(qualify_client)
        request = agent._create_request_openai_client(reason="protected_test")
        try:
            sdk = registry.enter(registry.permit, "sdk")
            def qualify_request() -> None:
                send = begin_chat_send(request)
                assert send is not None
                send.finish(SendOutcome(
                    kind="no_charge_proved", attempt_id=send.attempt_id,
                    reason="sdk_not_entered",
                ))
            sdk.run(qualify_request)
        finally:
            agent._close_request_openai_client(request, reason="request_complete")
        reused = agent._create_request_openai_client(reason="protected_reuse")
        assert reused is request
        agent._close_request_openai_client(reused, reason="request_complete")
        agent._close_cached_request_openai_client(reason="protected_evict")
        replacement = agent._create_request_openai_client(reason="protected_evicted")
        assert replacement is not request
        try:
            sdk = registry.enter(registry.permit, "sdk")
            sdk.run(lambda: _qualify_no_invocation(replacement))
        finally:
            agent._close_request_openai_client(replacement, reason="protected_evicted")
        assert agent._replace_primary_openai_client(reason="protected_rebuild")
        sdk = registry.enter(registry.permit, "sdk")
        sdk.run(lambda: _qualify_no_invocation(agent.client))
        for mutation in (
            lambda: agent._client_kwargs.__setitem__("base_url", "https://other.example/v1"),
            lambda: agent._client_kwargs.__setitem__("default_headers", {"X-Extra": "1"}),
        ):
            original = dict(agent._client_kwargs)
            mutation()
            with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
                agent._create_request_openai_client(reason="protected_drift")
            agent._client_kwargs = original
        original_key = agent.api_key
        agent.api_key = "different-key"
        with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
            agent._create_request_openai_client(reason="protected_key_drift")
        agent.api_key = original_key
        registry.request_close()
        with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
            agent._create_request_openai_client(reason="protected_closed")
        agent.client.close()

    try:
        executor.run(construct)
        assert calls == []
        assert manager._discovered
    finally:
        db.close()


def _qualify_no_invocation(client: object) -> None:
    send = begin_chat_send(client)
    assert send is not None
    send.finish(SendOutcome(
        kind="no_charge_proved", attempt_id=send.attempt_id,
        reason="sdk_not_entered",
    ))


def test_cold_protected_constructor_and_prompt_never_start_environment_probe(
    tmp_path: Path, monkeypatch
) -> None:
    from agent import system_prompt
    from tools import env_probe

    _, db, scope, _, _, prepared, writer, executor = _prepared(tmp_path, monkeypatch)
    calls: list[str] = []
    monkeypatch.setattr(
        env_probe, "warm_environment_probe_async", lambda: calls.append("warm")
    )
    monkeypatch.setattr(
        env_probe, "get_environment_probe_line", lambda: calls.append("lazy") or ""
    )

    def construct() -> None:
        with bind_write_permit(writer), bind_protected_constructor(prepared):
            agent = AIAgent(
                api_key=prepared.api_key,
                base_url=prepared.base_url,
                provider=prepared.provider,
                api_mode=prepared.api_mode,
                model=prepared.model,
                enabled_toolsets=["terminal_only"],
                session_id=scope.session_id,
                session_db=db,
                platform="api_server",
                quiet_mode=True,
                skip_memory=True,
                skip_background_review=True,
                skip_context_files=True,
            )
        assert agent._environment_probe is False
        system_prompt.build_system_prompt_parts(agent)
        assert calls == []
        agent.client.close()

    try:
        executor.run(construct)
    finally:
        db.close()


@pytest.mark.parametrize("change", ["base_url", "model", "config_json"])
def test_replaced_preparation_refuses_before_client(
    tmp_path: Path, monkeypatch, change: str
) -> None:
    import openai

    _, db, scope, _, _, prepared, writer, executor = _prepared(tmp_path, monkeypatch)
    replacement = {
        "base_url": "https://other.example/v1",
        "model": "redirected-model",
        "config_json": b'{"agent":{"environment_probe":true}}',
    }[change]
    changed = replace(prepared, **{change: replacement})
    calls: list[str] = []
    monkeypatch.setattr(
        openai, "OpenAI", lambda **_kwargs: calls.append("client") or object()
    )

    def construct() -> None:
        with (
            bind_write_permit(writer),
            pytest.raises(RecoveryRefused, match="unsupported_configuration"),
        ):
            with bind_protected_constructor(changed):
                AIAgent(
                    api_key=changed.api_key,
                    base_url=changed.base_url,
                    provider=changed.provider,
                    api_mode=changed.api_mode,
                    model=changed.model,
                    enabled_toolsets=["terminal_only"],
                    session_id=scope.session_id,
                    session_db=db,
                    platform="api_server",
                    quiet_mode=True,
                    skip_memory=True,
                    skip_background_review=True,
                    skip_context_files=True,
                )

    try:
        executor.run(construct)
        assert calls == []
    finally:
        db.close()


def test_admitted_agent_without_preparation_refuses_before_client(
    tmp_path: Path, monkeypatch
) -> None:
    owner = _profile(tmp_path, monkeypatch)
    db, store, scope, registry = _admitted(owner.home)
    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation
    )
    calls: list[str] = []
    monkeypatch.setattr(
        AIAgent, "_create_openai_client", lambda *_a, **_k: calls.append("client")
    )
    executor = registry.enter(registry.permit, "executor")

    def construct() -> None:
        with (
            bind_write_permit(writer),
            pytest.raises(RecoveryRefused, match="unsupported_configuration"),
        ):
            AIAgent(
                api_key="sk-scratch-constructor-only",
                base_url="https://api.openai.com/v1",
                provider="openai-api",
                api_mode="chat_completions",
                model="gpt-4.1",
                enabled_toolsets=["terminal_only"],
                session_id=scope.session_id,
                session_db=db,
                quiet_mode=True,
            )

    try:
        executor.run(construct)
        assert calls == []
    finally:
        db.close()


def test_routing_drift_refuses_before_client(tmp_path: Path, monkeypatch) -> None:
    from agent import agent_init

    _, db, scope, registry, _, prepared, writer, executor = _prepared(
        tmp_path, monkeypatch
    )
    original = agent_init._finalize_routing
    calls: list[str] = []

    def drift(agent, api_mode, credential_pool) -> None:
        original(agent, api_mode, credential_pool)
        agent.model = "different-model"

    monkeypatch.setattr(agent_init, "_finalize_routing", drift)
    monkeypatch.setattr(
        AIAgent, "_create_openai_client", lambda *_a, **_k: calls.append("client")
    )

    def construct() -> None:
        with (
            bind_write_permit(writer),
            pytest.raises(RecoveryRefused, match="unsupported_configuration"),
        ):
            with bind_protected_constructor(prepared):
                AIAgent(
                    api_key=prepared.api_key,
                    base_url=prepared.base_url,
                    provider=prepared.provider,
                    api_mode=prepared.api_mode,
                    model=prepared.model,
                    enabled_toolsets=["terminal_only"],
                    session_id=scope.session_id,
                    session_db=db,
                    platform="api_server",
                    quiet_mode=True,
                    skip_memory=True,
                    skip_background_review=True,
                    skip_context_files=True,
                )

    try:
        executor.run(construct)
        assert calls == []
    finally:
        db.close()


@pytest.mark.parametrize("drift", ["config", "key", "manager", "provider", "tools"])
def test_prepared_constructor_refuses_drift_before_client(
    tmp_path: Path, monkeypatch, drift: str
) -> None:
    from tools.registry import registry as tool_registry
    from tools import terminal_tool_config

    owner, db, _, registry, manager, prepared, writer, executor = _prepared(
        tmp_path, monkeypatch
    )
    calls: list[str] = []
    monkeypatch.setattr(
        AIAgent, "_create_openai_client", lambda *_a, **_k: calls.append("client")
    )
    if drift == "config":
        config = owner.home / "config.yaml"
        config.write_text(
            config.read_text(encoding="utf-8").replace("gpt-4.1", "gpt-4.2"),
            encoding="utf-8",
        )
    elif drift == "key":
        monkeypatch.setenv("OPENAI_API_KEY", "sk-rotated-constructor-key")
    elif drift == "manager":
        monkeypatch.setattr(manager, "_discovered", False)
    elif drift == "provider":
        monkeypatch.setattr(
            terminal_tool_config, "_get_plugin_env_provider", lambda _: object()
        )
    else:
        monkeypatch.setattr(tool_registry, "_generation", tool_registry._generation + 1)

    def construct() -> None:
        with (
            bind_write_permit(writer),
            pytest.raises(RecoveryRefused, match="unsupported_configuration"),
        ):
            with bind_protected_constructor(prepared):
                AIAgent(
                    api_key=prepared.api_key,
                    base_url=prepared.base_url,
                    provider=prepared.provider,
                    api_mode=prepared.api_mode,
                    model=prepared.model,
                    enabled_toolsets=["terminal_only"],
                    session_id=registry.scope.session_id,
                    session_db=db,
                    platform="api_server",
                    quiet_mode=True,
                    skip_memory=True,
                    skip_background_review=True,
                    skip_context_files=True,
                )

    try:
        executor.run(construct)
        assert calls == []
    finally:
        db.close()


def test_prepared_constructor_refuses_busy_discovery_lock_without_waiting(
    tmp_path: Path, monkeypatch
) -> None:
    _, db, _, _, manager, prepared, writer, executor = _prepared(tmp_path, monkeypatch)
    acquired = Event()
    release = Event()

    def hold_lock() -> None:
        with manager._discovery_lock:
            acquired.set()
            assert release.wait(5)

    worker = Thread(target=hold_lock)
    worker.start()
    try:
        assert acquired.wait(5)

        def attempt() -> None:
            with (
                bind_write_permit(writer),
                pytest.raises(RecoveryRefused, match="unsupported_configuration"),
            ):
                with bind_protected_constructor(prepared):
                    pass

        executor.run(attempt)
    finally:
        release.set()
        worker.join(5)
        db.close()
    assert not worker.is_alive()


def test_preparation_does_not_serialize_or_represent_credential(
    tmp_path: Path, monkeypatch
) -> None:
    _, db, _, _, _, prepared, _, _ = _prepared(tmp_path, monkeypatch)
    try:
        assert prepared.api_key not in repr(prepared)
        assert prepared.api_key.encode() not in prepared.config_json
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(prepared)
    finally:
        db.close()
