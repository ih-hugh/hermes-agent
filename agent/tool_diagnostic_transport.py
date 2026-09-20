"""Narrow, observational hooks beside Hermes's own SDK invocations."""

from __future__ import annotations

import hashlib
from typing import Any

from agent.tool_diagnostic import ToolSendObserver, current_tool_send_observer

_BRIDGE_NAMES = frozenset({"tool_search", "tool_describe", "tool_call"})
_SUPPORTED_TOOLSETS = frozenset({"terminal", "file", "todo", "no_mcp"})


def _pure_drift_markers() -> tuple[int, str]:
    from tools.registry import registry
    from tools.tool_search import load_config_readonly

    config_digest = hashlib.sha256(repr(load_config_readonly()).encode()).hexdigest()
    return registry._generation, config_digest


def _extensions_active() -> bool:
    """Read already-loaded extension state; never discover or invoke a plugin."""
    from hermes_cli.plugins import get_plugin_manager

    manager = get_plugin_manager()
    return bool(
        any(getattr(plugin, "enabled", False) for plugin in manager._plugins.values())
        or any(manager._middleware.values())
        or any(manager._hooks.values())
        or getattr(manager, "_aux_tasks", None)
        or getattr(manager, "_context_engine", None)
        or getattr(manager, "_subscriptions", None)
        or getattr(manager, "_plugin_tool_names", None)
        or getattr(manager, "_persistent_carryover", None)
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
        if _extensions_active():
            observer.mark_incomplete("unsupported_configuration")
        observer.set_drift_markers(*_pure_drift_markers())
    except Exception:
        observer.mark_incomplete("capture_failed")


def _check_pure_drift(observer: ToolSendObserver) -> None:
    try:
        observer.check_drift_markers(*_pure_drift_markers())
        if _extensions_active():
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
        _check_pure_drift(observer)
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

        _check_pure_drift(observer)
        observer.observe_scope(
            tuple(sorted(scoped_deferrable_names(current_defs))), True
        )
    except Exception:
        observer.mark_incomplete("capture_failed")


def mark_auxiliary_send() -> None:
    observer = current_tool_send_observer.get()
    if observer is not None:
        observer.mark_incomplete("unsupported_call_role")
