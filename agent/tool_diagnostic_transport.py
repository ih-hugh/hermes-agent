"""Narrow, observational hooks beside Hermes's own SDK invocations."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from agent.tool_diagnostic import ToolSendObserver, current_tool_send_observer

_BRIDGE_NAMES = frozenset({"tool_search", "tool_describe", "tool_call"})
# `no_mcp` is a config sentinel removed by _get_platform_tools before it
# passes enabled_toolsets to AIAgent. Observe the resolved runtime selection.
_SUPPORTED_TOOLSETS = frozenset({"terminal", "file", "todo"})
_RAFT_HOOK_FUNCTIONS = {
    "on_session_start": "_on_session_start",
    "on_session_end": "_on_session_end",
    "on_session_finalize": "_on_session_finalize",
    "pre_llm_call": "_on_pre_llm_call",
    "post_llm_call": "_on_post_llm_call",
    "pre_tool_call": "_on_pre_tool_call",
    "post_tool_call": "_on_post_tool_call",
}
_BUNDLED_RAFT_ADAPTER = (
    Path(__file__).resolve().parents[1] / "plugins/platforms/raft/adapter.py"
).resolve()
_BUNDLED_PLUGIN_ROOT = _BUNDLED_RAFT_ADAPTER.parents[2]
_STOCK_GATEWAY_INBOUND = (
    Path(__file__).resolve().parents[1] / "gateway/run_inbound.py"
).resolve()
_STOCK_GATEWAY_RUN = (Path(__file__).resolve().parents[1] / "gateway/run.py").resolve()
_UNOBSERVED_CALLBACK_REGISTRIES = (
    "_plugin_commands",
    "_system_prompt_sections",
    "_approval_transports",
    "_slack_action_handlers",
    "_platform_handler_factories",
    "_memory_hook_registrations",
)


def _only_stock_raft_hooks(hooks: dict[str, list[Any]]) -> bool:
    """Allow exact, already-loaded Raft activity callbacks only.

    The bundled adapter's `_raft_hook` gate runs its body only for Raft
    sessions; its body emits platform activity and makes no model SDK call.
    Never import a module, discover a plugin, or invoke a callback here.
    """
    for kind, callbacks in hooks.items():
        expected_name = _RAFT_HOOK_FUNCTIONS.get(kind)
        if expected_name is None or len(callbacks) != 1:
            return False
        callback = callbacks[0]
        module = sys.modules.get(getattr(callback, "__module__", ""))
        if module is None:
            return False
        source = getattr(module, "__file__", None)
        code = getattr(callback, "__code__", None)
        if (
            not isinstance(source, str)
            or Path(source).resolve() != _BUNDLED_RAFT_ADAPTER
            or code is None
            or Path(code.co_filename).resolve() != _BUNDLED_RAFT_ADAPTER
            or getattr(module, expected_name, None) is not callback
        ):
            return False
    return True


def _only_stock_gateway_injector(registration: object) -> bool:
    """Accept only the core GatewayRunner scheduler, without loading or calling it."""
    if registration is None:
        return True
    if not isinstance(registration, tuple) or len(registration) != 2:
        return False
    owner, callback = registration
    inbound_module = sys.modules.get("gateway.run_inbound")
    run_module = sys.modules.get("gateway.run")
    if inbound_module is None or run_module is None:
        return False
    inbound_class = vars(inbound_module).get("GatewayInboundMixin")
    runner_class = vars(run_module).get("GatewayRunner")
    function = getattr(callback, "__func__", None)
    code = getattr(function, "__code__", None)
    return bool(
        isinstance(getattr(inbound_module, "__file__", None), str)
        and Path(inbound_module.__file__).resolve() == _STOCK_GATEWAY_INBOUND
        and isinstance(getattr(run_module, "__file__", None), str)
        and Path(run_module.__file__).resolve() == _STOCK_GATEWAY_RUN
        and type(owner) is runner_class
        and getattr(callback, "__self__", None) is owner
        and inbound_class is not None
        and vars(inbound_class).get("_schedule_plugin_message_injection") is function
        and code is not None
        and Path(code.co_filename).resolve() == _STOCK_GATEWAY_INBOUND
    )


def _pure_drift_markers() -> tuple[int, str]:
    from tools.registry import registry
    from tools.tool_search import load_config_readonly

    config_digest = hashlib.sha256(repr(load_config_readonly()).encode()).hexdigest()
    return registry._generation, config_digest


def _extensions_active(selected_tool_names: set[str]) -> bool:
    """Reject reachable callbacks/tools, without discovering or invoking plugins."""
    from hermes_cli.plugins import get_plugin_manager

    manager = get_plugin_manager()
    hooks = {kind: callbacks for kind, callbacks in manager._hooks.items() if callbacks}
    # User/project/entry-point plugin setup can perform sends even if it leaves
    # no registered tool or callback. The stock bundled tree is assessed by
    # reachable registrations below, rather than by its installed plugin count.
    external_plugin = any(
        getattr(plugin, "enabled", False)
        and (
            getattr(getattr(plugin, "manifest", None), "source", None) != "bundled"
            or not isinstance(getattr(plugin.manifest, "path", None), str)
            or not Path(plugin.manifest.path)
            .resolve()
            .is_relative_to(_BUNDLED_PLUGIN_ROOT)
        )
        for plugin in manager._plugins.values()
    )
    return bool(
        external_plugin
        or any(manager._middleware.values())
        or (hooks and not _only_stock_raft_hooks(hooks))
        or getattr(manager, "_aux_tasks", None)
        or getattr(manager, "_context_engine", None)
        or getattr(manager, "_subscriptions", None)
        or getattr(manager, "_persistent_carryover", None)
        or not _only_stock_gateway_injector(
            getattr(manager, "_gateway_message_injector", None)
        )
        or any(getattr(manager, name, None) for name in _UNOBSERVED_CALLBACK_REGISTRIES)
        or selected_tool_names & set(getattr(manager, "_plugin_tool_names", ()))
    )


def bind_agent_tool_scope(agent: Any, observer: ToolSendObserver) -> None:
    """Remember pure drift markers after the ordinary agent tool load."""
    try:
        from tools.registry import registry

        names, active = observer.frozen_scope()
        enabled_toolsets = getattr(agent, "enabled_toolsets", None)
        if not isinstance(enabled_toolsets, (list, tuple, set, frozenset)) or (
            frozenset(enabled_toolsets) != _SUPPORTED_TOOLSETS
        ):
            observer.mark_incomplete("unsupported_configuration")
        if (
            getattr(agent, "api_mode", None) != "chat_completions"
            or getattr(agent, "provider", None) == "moa"
        ):
            observer.mark_incomplete("unsupported_api_mode")
        from agent.gemini_native_adapter import is_native_gemini_base_url

        if is_native_gemini_base_url(str(getattr(agent, "base_url", ""))):
            observer.mark_incomplete("unsupported_api_mode")
        tool_names = {item["function"]["name"] for item in (agent.tools or [])}
        if bool(_BRIDGE_NAMES & tool_names) != active:
            observer.mark_incomplete("scope_changed")
        if (
            getattr(agent, "_tool_snapshot_generation", registry._generation)
            != registry._generation
        ):
            observer.mark_incomplete("scope_changed")
        if _extensions_active(tool_names | set(names)):
            observer.mark_incomplete("unsupported_configuration")
        observer.set_drift_markers(*_pure_drift_markers())
    except Exception:
        observer.mark_incomplete("capture_failed")


def _check_pure_drift(
    observer: ToolSendObserver, selected_tool_names: set[str]
) -> None:
    try:
        observer.check_drift_markers(*_pure_drift_markers())
        if _extensions_active(selected_tool_names):
            observer.mark_incomplete("unsupported_configuration")
    except Exception:
        observer.mark_incomplete("capture_failed")


def observe_sdk_send(
    agent: Any, sdk_kwargs: dict[str, Any], *, call_role: str = "main"
) -> None:
    """Capture the exact final tool value; never affect a provider send."""
    observer: ToolSendObserver | None = getattr(agent, "_tool_send_observer", None)
    if observer is None:
        return
    try:
        tools = sdk_kwargs.get("tools", [])
        names, active = observer.frozen_scope()
        actual_names = (
            {
                item.get("function", {}).get("name")
                for item in tools
                if isinstance(item, dict) and isinstance(item.get("function"), dict)
            }
            if isinstance(tools, list)
            else set()
        )
        actual_active = _BRIDGE_NAMES.issubset(actual_names)
        _check_pure_drift(
            observer,
            {name for name in actual_names if isinstance(name, str)} | set(names),
        )
        if active != actual_active:
            observer.mark_incomplete("scope_changed")
        observer.observe_scope(names, actual_active)
        api_mode = str(getattr(agent, "api_mode", ""))
        provider = str(getattr(agent, "provider", ""))
        if provider == "moa":
            api_mode = "unsupported_moa"
        from agent.gemini_native_adapter import is_native_gemini_base_url

        if is_native_gemini_base_url(str(getattr(agent, "base_url", ""))):
            api_mode = "unsupported_gemini_native"
        observer.capture_sdk_send(
            getattr(agent, "_current_api_request_id", ""),
            api_mode,
            call_role,
            tools,
            deferred_tool_names=names if actual_active else (),
            tool_search_active=actual_active,
        )
    except Exception:
        observer.mark_incomplete("capture_failed")


def mark_unsupported_send(
    agent: Any, sdk_kwargs: dict[str, Any], *, call_role: str = "main"
) -> None:
    observer: ToolSendObserver | None = getattr(agent, "_tool_send_observer", None)
    if observer is None:
        return
    try:
        observer.capture_sdk_send(
            getattr(agent, "_current_api_request_id", ""),
            str(getattr(agent, "api_mode", "unsupported")),
            call_role,
            sdk_kwargs.get("tools", []),
            deferred_tool_names=(),
            tool_search_active=False,
        )
        observer.mark_incomplete(
            "unsupported_api_mode" if call_role == "main" else "unsupported_call_role"
        )
    except Exception:
        observer.mark_incomplete("capture_failed")


def observe_bridge_dispatch(current_defs: list[dict[str, Any]]) -> None:
    """Compare already-resolved bridge scope; dispatch remains authorized by current_defs."""
    observer = current_tool_send_observer.get()
    if observer is None:
        return
    try:
        from tools.tool_search import scoped_deferrable_names

        scoped_names = tuple(sorted(scoped_deferrable_names(current_defs)))
        _check_pure_drift(observer, set(scoped_names))
        observer.observe_scope(scoped_names, True)
    except Exception:
        observer.mark_incomplete("capture_failed")


def mark_auxiliary_send() -> None:
    observer = current_tool_send_observer.get()
    if observer is not None:
        observer.mark_incomplete("unsupported_call_role")
