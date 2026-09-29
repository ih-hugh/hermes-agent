"""Protected chat turns use the actual resolved tool and request surfaces."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from agent.recovery_context import bind_write_permit, issue_write_permit
from agent.recovery_producers import (
    require_supported_chat_agent,
    require_effective_chat_request,
)
from hermes_state import SessionDB
from hermes_cli.tools_config import _get_platform_tools
from hermes_state_recovery import RecoveryRefused
from run_agent import AIAgent
from tests.agent.test_recovery_runtime import (
    _admitted,
    _install_selected_plugin_fixture,
)


def _real_agent(tmp_path: Path, *, toolsets: list[str]) -> tuple[AIAgent, SessionDB]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = SessionDB(tmp_path / "state.db")
    agent = AIAgent(
        api_key="scratch-only",
        base_url="http://127.0.0.1:9/v1",
        provider="openai",
        api_mode="chat_completions",
        model="gpt-4o",
        enabled_toolsets=toolsets,
        session_id="scratch-tools",
        session_db=db,
        platform="api_server",
        quiet_mode=True,
        skip_memory=True,
        skip_background_review=True,
        skip_context_files=True,
    )
    return agent, db


def _scratch_home(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text(
        "model:\n  context_length: 128000\ntools:\n  tool_search:\n    enabled: 'off'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))


def _with_protected_agent(
    tmp_path: Path, monkeypatch, check: Callable[[AIAgent], None]
) -> None:
    from agent.recovery_producers import bind_protected_constructor
    from gateway.platforms.api_server_recovery import RecoveryOwnerContext
    from gateway.platforms.api_server_recovery_runtime import (
        prepare_static_chat_runtime,
    )

    _scratch_home(tmp_path, monkeypatch)
    home = tmp_path / "hermes-home"
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
        "platform_toolsets:\n  api_server: [terminal_only, no_mcp]\n"
        "tools:\n  tool_search:\n    enabled: 'off'\n"
        "terminal:\n  backend: byf_workspace\n"
        "context:\n  engine: compressor\n"
        "model:\n  provider: openai-api\n  api_mode: chat_completions\n"
        "  default: gpt-4.1\n  context_length: 128000\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "sk-scratch-constructor-only")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(
        "hermes_cli.profiles.get_active_profile_name", lambda: "factory"
    )
    db, store, scope, registry = _admitted(tmp_path)
    _install_selected_plugin_fixture(registry, monkeypatch)
    prepared = prepare_static_chat_runtime(
        RecoveryOwnerContext("factory", home, scope.scope_digest),
        session_id=scope.session_id,
    )
    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation
    )
    executor = registry.enter(registry.permit, "executor")

    def body() -> None:
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
        with monkeypatch.context() as patch:
            _install_selected_plugin_fixture(registry, patch)
            check(agent)

    try:
        executor.run(body)
    finally:
        db.close()


def test_real_agent_terminal_only_resolves_one_tool_and_actual_kwargs(
    tmp_path: Path, monkeypatch
):
    _scratch_home(tmp_path, monkeypatch)
    legacy, legacy_db = _real_agent(tmp_path / "legacy", toolsets=["terminal"])
    try:
        assert {tool["function"]["name"] for tool in legacy.tools} == {
            "terminal",
            "process_manage",
        }
    finally:
        legacy_db.close()

    selected = _get_platform_tools(
        {"platform_toolsets": {"api_server": ["terminal_only", "no_mcp"]}},
        "api_server",
    )
    assert selected == {"terminal_only"}
    agent, db = _real_agent(tmp_path / "selected", toolsets=sorted(selected))
    try:
        assert agent.valid_tool_names == {"terminal"}
        assert [tool["function"]["name"] for tool in agent.tools] == ["terminal"]
        kwargs = agent._build_api_kwargs([{"role": "user", "content": "scratch"}])
        assert kwargs["model"] == agent.model
        assert kwargs["tools"] == agent.tools
        assert "extra_body" not in kwargs
    finally:
        db.close()


def test_actual_protected_agent_and_request_are_qualified(tmp_path: Path, monkeypatch):
    def check(agent: AIAgent) -> None:
        require_supported_chat_agent(agent)
        kwargs = agent._build_api_kwargs([{"role": "user", "content": "scratch"}])
        require_effective_chat_request(agent, kwargs, expected_stream=False)

    _with_protected_agent(tmp_path, monkeypatch, check)


@pytest.mark.parametrize("streaming", [False, True])
def test_real_protected_agent_reaches_one_physical_create(
    tmp_path: Path, monkeypatch, streaming: bool
):
    from types import SimpleNamespace

    from openai import OpenAI

    from agent import chat_completion_helpers as helpers
    from agent import tool_diagnostic_transport
    from agent.recovery_producers import current_registry, finish_unknown_if_active

    client = OpenAI(api_key="scratch-only", max_retries=0)
    creates: list[dict[str, object]] = []
    monkeypatch.setattr(
        client.chat.completions,
        "create",
        lambda **kwargs: creates.append(kwargs) or object(),
    )
    monkeypatch.setattr(tool_diagnostic_transport, "observe_sdk_send", lambda *_: None)

    def check(agent: AIAgent) -> None:
        registry = current_registry()
        assert registry is not None
        kwargs = agent._build_api_kwargs([{"role": "user", "content": "scratch"}])
        sdk = registry.enter(registry.permit, "sdk")

        def invoke() -> None:
            if streaming:
                monkeypatch.setattr(
                    agent, "_create_request_openai_client", lambda **_: client
                )
                driver = SimpleNamespace(
                    agent=agent,
                    clients=SimpleNamespace(set_client=lambda value: value),
                    last_chunk_time={},
                )
                helpers._StreamingCall._open_chat_stream(
                    driver, {**kwargs, "stream": True}
                )
                finish_unknown_if_active(driver._recovery_send, "usage_unavailable")
            else:
                response = helpers._dispatch_nonstreaming_api_request(
                    agent, kwargs, make_client=lambda *_: client
                )
                send = registry.claim_response_send(response)
                assert send is not None
                finish_unknown_if_active(send, "usage_unavailable")

        sdk.run(invoke)
        assert len(creates) == 1
        assert len(registry.store.send_inventory(registry.scope, registry.run_id)) == 1
        assert creates[0]["tools"] == agent.tools

    try:
        _with_protected_agent(tmp_path, monkeypatch, check)
    finally:
        client.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "stale_names",
        "schema",
        "bridge",
        "native",
        "memory",
        "handler_override",
        "extra_body",
        "model",
        "tools",
        "extra_query",
        "unknown_kwarg",
    ],
)
def test_actual_protected_agent_or_request_drift_refuses(
    tmp_path: Path, monkeypatch, mutation: str
):
    def check(agent: AIAgent) -> None:
        kwargs = agent._build_api_kwargs([{"role": "user", "content": "scratch"}])
        if mutation == "duplicate":
            agent.tools.append(dict(agent.tools[0]))
        elif mutation == "stale_names":
            agent.valid_tool_names.add("process_manage")
        elif mutation == "schema":
            agent.tools[0]["function"]["description"] = "different"
        elif mutation == "bridge":
            agent.tools.append({
                "type": "function",
                "function": {"name": "tool_search"},
            })
        elif mutation == "native":
            agent.enabled_toolsets.append("browser")
        elif mutation == "memory":
            agent._memory_manager = object()
        elif mutation == "handler_override":
            from dataclasses import replace
            from tools.registry import registry as tool_registry

            original = tool_registry.get_entry
            monkeypatch.setattr(
                tool_registry,
                "get_entry",
                lambda name: replace(
                    original(name), handler=lambda *_a, **_kw: "other"
                ),
            )
        elif mutation == "extra_body":
            kwargs["extra_body"] = {"tools": []}
        elif mutation == "model":
            kwargs["model"] = "other"
        elif mutation == "tools":
            kwargs["tools"] = []
        elif mutation == "extra_query":
            kwargs["extra_query"] = {"route": "other"}
        else:
            kwargs["unreviewed_extension"] = {"tools": []}
        with pytest.raises(RecoveryRefused):
            if mutation in {
                "duplicate",
                "stale_names",
                "schema",
                "bridge",
                "native",
                "memory",
                "handler_override",
            }:
                require_supported_chat_agent(agent)
            else:
                require_effective_chat_request(agent, kwargs, expected_stream=False)

    _with_protected_agent(tmp_path, monkeypatch, check)


@pytest.mark.parametrize(
    "registration",
    [
        "missing",
        "wrong_kind",
        "extra_active",
        "second_plugin",
        "callback",
        "middleware",
    ],
)
def test_selected_plugin_inventory_requires_exact_registration(
    tmp_path: Path, monkeypatch, registration: str
):
    from hermes_cli.plugins import LoadedPlugin, get_plugin_manager
    from hermes_cli.plugins_ledger import PluginRegistration
    from hermes_cli.plugins_manifest import PluginManifest

    def check(agent: AIAgent) -> None:
        manager = get_plugin_manager()
        if registration == "missing":
            manager._plugins.pop("byf_workspace")
        elif registration == "wrong_kind":
            manager._ownership_ledger["byf_workspace"][0].kind = "hook"
        elif registration == "extra_active":
            manager._ownership_ledger["byf_workspace"].append(
                PluginRegistration(
                    kind="hook",
                    key="pre_api_request",
                    release=lambda: None,
                    plugin_key="byf_workspace",
                )
            )
        elif registration == "second_plugin":
            manager._plugins["other"] = LoadedPlugin(
                manifest=PluginManifest(name="other", source="user"),
                module=manager._plugins["byf_workspace"].module,
                enabled=True,
            )
        elif registration == "callback":
            monkeypatch.setattr(
                manager,
                "_hooks",
                {**manager._hooks, "pre_api_request": [lambda **_: None]},
            )
        else:
            monkeypatch.setattr(
                manager,
                "_middleware",
                {**manager._middleware, "llm_request": [lambda **_: None]},
            )
        with pytest.raises(RecoveryRefused):
            require_supported_chat_agent(agent)

    _with_protected_agent(tmp_path, monkeypatch, check)


@pytest.mark.parametrize("cause", ["inline_moa", "fallback", "context_engine"])
def test_early_turn_guard_refuses_before_context_or_moa_effect(
    tmp_path: Path, monkeypatch, cause: str
):
    from agent import conversation_loop

    def check(agent: AIAgent) -> None:
        context_calls: list[object] = []
        monkeypatch.setattr(
            conversation_loop,
            "build_turn_context",
            lambda *_args, **_kwargs: context_calls.append(True),
        )
        if cause == "fallback":
            agent._fallback_chain = [{"provider": "other", "model": "other"}]
        elif cause == "context_engine":
            agent.context_compressor = object()
        with pytest.raises(RecoveryRefused):
            conversation_loop._run_conversation_turn(
                agent, "scratch", moa_config={} if cause == "inline_moa" else None
            )
        assert context_calls == []

    _with_protected_agent(tmp_path, monkeypatch, check)
