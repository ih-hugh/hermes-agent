"""The names-only send observer must reconcile actual invocations safely."""

import hashlib
import importlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from openai import OpenAI

from agent.tool_diagnostic import ToolSendObserver


def _tool(name):
    return {
        "type": "function",
        "function": {"name": name, "parameters": {"type": "object"}},
    }


def test_recorded_sdk_schemas_are_ordered_and_digestible():
    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456)
    schemas = [_tool("read_file"), _tool("tool_call")]
    internal_id = "session-DONOTLEAK:api:1"
    observer.capture_sdk_send(
        internal_id,
        "chat_completions",
        "main",
        schemas,
        deferred_tool_names=("terminal",),
        tool_search_active=True,
    )
    observer.close_producer()
    report = observer.snapshot()
    assert report["state"] == "complete"
    assert report["attempts"] == [
        {
            "api_request_id": hashlib.sha256(internal_id.encode()).hexdigest(),
            "attempt_index": 1,
            "api_mode": "chat_completions",
            "call_role": "main",
            "advertised_tool_names": ["read_file", "tool_call"],
            "tool_schema_sha256": hashlib.sha256(
                json.dumps(
                    schemas, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest(),
            "deferred_tool_names": ["terminal"],
            "tool_search_active": True,
        }
    ]
    assert "DONOTLEAK" not in json.dumps(report)


def test_worker_must_close_after_cancelled_waiter_and_bad_schema_never_leaks():
    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456)
    observer.register_worker()
    observer.capture_sdk_send(
        "session-DONOTLEAK:api:1",
        "chat_completions",
        "main",
        [{"secret": "DONOTLEAK"}],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.close_producer()
    assert observer.snapshot()["state"] == "pending"
    observer.close_worker()
    report = observer.snapshot()
    assert report["state"] == "incomplete"
    assert report["reason"] == "capture_failed"
    assert "DONOTLEAK" not in json.dumps(report)


def test_late_registered_worker_revokes_settlement():
    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456)
    observer.capture_sdk_send(
        "request_x",
        "chat_completions",
        "main",
        [],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.close_producer()
    assert observer.snapshot()["state"] == "complete"
    observer.register_worker()
    assert observer.snapshot()["state"] == "pending"
    observer.close_worker()
    assert observer.snapshot()["reason"] == "capture_failed"


def test_capacity_and_expiry_fail_closed():
    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456, max_attempts=1)
    observer.capture_sdk_send(
        "one",
        "chat_completions",
        "main",
        [],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.capture_sdk_send(
        "two",
        "chat_completions",
        "main",
        [],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.close_producer()
    assert observer.snapshot()["reason"] == "limit_exceeded"
    observer.expire()
    assert observer.snapshot()["state"] == "expired"
    assert observer.snapshot()["attempts"] == []


def test_real_openai_sdk_serialization_matches_captured_schema(monkeypatch, tmp_path):
    """The supported chat path must match the JSON seen by a loopback provider."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            payload = {
                "id": "chatcmpl-local",
                "object": "chat.completion",
                "created": 1,
                "model": "local",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ok"},
                    }
                ],
            }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    client = OpenAI(
        api_key="local-test",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
        max_retries=0,
    )
    try:
        from agent.chat_completion_helpers import _dispatch_nonstreaming_api_request
        from agent.tool_diagnostic_transport import _pure_drift_markers

        observer = ToolSendObserver("run_local", "default", "owner", 123, 456)
        observer.set_tool_scope((), (), False)
        observer.set_drift_markers(*_pure_drift_markers())
        agent = SimpleNamespace(
            api_mode="chat_completions",
            provider="nous",
            _current_api_request_id="request_local",
            _tool_send_observer=observer,
        )
        schemas = [_tool("read_file"), _tool("patch")]
        result = _dispatch_nonstreaming_api_request(
            agent,
            {
                "model": "local",
                "messages": [{"role": "user", "content": "hi"}],
                "tools": schemas,
            },
            make_client=lambda _reason: client,
        )
        observer.close_producer()
        assert result.choices[0].message.content == "ok"
        assert [tool["function"]["name"] for tool in received[0]["tools"]] == (
            observer.snapshot()["attempts"][0]["advertised_tool_names"]
        )
        assert observer.snapshot()["state"] == "complete"
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        server_thread.join()


def test_stream_resend_captures_each_final_sdk_argument_set(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(body)
            if len(received) == 1:
                data = json.dumps({
                    "error": {
                        "message": "unsupported stream_options",
                        "type": "invalid_request_error",
                    }
                }).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            chunk = {
                "id": "chunk-local",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "local",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            }
            data = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    client = OpenAI(
        api_key="local-test",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
        max_retries=0,
    )
    try:
        from agent.chat_completion_helpers import _StreamingCall
        from agent.tool_diagnostic_transport import _pure_drift_markers

        observer = ToolSendObserver("run_stream", "default", "owner", 123, 456)
        observer.set_tool_scope((), (), False)
        observer.set_drift_markers(*_pure_drift_markers())
        agent = SimpleNamespace(
            base_url=str(client.base_url),
            api_mode="chat_completions",
            provider="nous",
            _current_api_request_id="request_stream",
            _stream_options_unsupported=False,
            _tool_send_observer=observer,
            _create_request_openai_client=lambda **_kw: client,
            _touch_activity=lambda *_args: None,
        )
        call = SimpleNamespace(
            agent=agent,
            clients=SimpleNamespace(set_client=lambda value: value),
            last_chunk_time={},
        )
        kwargs = {
            "model": "local",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [_tool("patch")],
            "stream": True,
        }
        with pytest.raises(Exception):
            _StreamingCall._open_chat_stream(call, dict(kwargs))
        agent._stream_options_unsupported = True
        stream = _StreamingCall._open_chat_stream(call, dict(kwargs))
        list(stream)
        stream.close()
        observer.close_producer()
        assert "stream_options" in received[0]
        assert "stream_options" not in received[1]
        report = observer.snapshot()
        assert report["state"] == "complete"
        assert [attempt["attempt_index"] for attempt in report["attempts"]] == [1, 2]
        assert all(
            attempt["advertised_tool_names"] == ["patch"]
            for attempt in report["attempts"]
        )
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        server_thread.join()


def test_bridge_scope_drift_is_incomplete_without_changing_dispatch(monkeypatch):
    import model_tools
    from agent.tool_diagnostic import current_tool_send_observer
    from tools import tool_search as ts

    monkeypatch.setattr(
        "agent.tool_diagnostic_transport._extensions_active", lambda _names: False
    )

    cfg = ts.ToolSearchConfig.from_raw({"enabled": "on", "defer": ["process_manage"]})
    monkeypatch.setattr(ts, "load_config_readonly", lambda: cfg)
    current_defs = [_tool("process_manage")]
    monkeypatch.setattr(model_tools, "get_tool_definitions", lambda **_kw: current_defs)
    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456)
    observer.set_tool_scope(("process_manage",), ("process_manage",), True)
    from agent.tool_diagnostic_transport import _pure_drift_markers

    observer.set_drift_markers(*_pure_drift_markers())
    token = current_tool_send_observer.set(observer)
    try:
        for bridge_name, args in (
            ("tool_search", {"queries": ["process"]}),
            ("tool_describe", {"names": ["process_manage"]}),
            ("tool_call", {"name": "process_manage", "arguments": {"action": "list"}}),
        ):
            with_observer = model_tools._dispatch_bridge_tool(
                bridge_name, args, None, None
            )
            off = current_tool_send_observer.set(None)
            without_observer = model_tools._dispatch_bridge_tool(
                bridge_name, args, None, None
            )
            current_tool_send_observer.reset(off)
            assert with_observer == without_observer
        current_defs = []
        drift_result = model_tools._dispatch_bridge_tool(
            "tool_call",
            {"name": "process_manage", "arguments": {"action": "list"}},
            None,
            None,
        )
        off = current_tool_send_observer.set(None)
        control_result = model_tools._dispatch_bridge_tool(
            "tool_call",
            {"name": "process_manage", "arguments": {"action": "list"}},
            None,
            None,
        )
        current_tool_send_observer.reset(off)
        assert drift_result == control_result
        observer.close_producer()
        assert observer.snapshot()["reason"] == "scope_changed"
    finally:
        current_tool_send_observer.reset(token)


def test_ordinary_tool_selection_records_same_scope_on_cache_hit(monkeypatch, tmp_path):
    import model_tools
    from agent.tool_diagnostic import current_tool_send_observer
    from tools import tool_search as ts

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg = ts.ToolSearchConfig.from_raw({
        "enabled": "on",
        "defer": ["process_manage", "todo_list"],
    })
    monkeypatch.setattr(ts, "load_config", lambda: cfg)
    monkeypatch.setattr(ts, "load_config_readonly", lambda: cfg)
    model_tools._clear_tool_defs_cache()
    scopes = []
    names = []
    for run_id in ("run_first", "run_cached"):
        observer = ToolSendObserver(run_id, "builder", "owner", 123, 456)
        token = current_tool_send_observer.set(observer)
        try:
            definitions = model_tools.get_tool_definitions(
                enabled_toolsets=["terminal", "file", "todo"], quiet_mode=True
            )
        finally:
            current_tool_send_observer.reset(token)
        scopes.append(observer.frozen_scope())
        names.append({item["function"]["name"] for item in definitions})
    assert scopes[0] == scopes[1]
    assert names[0] == names[1]
    assert scopes[0][1] is True
    assert {"tool_search", "tool_describe", "tool_call"} <= names[0]
    assert set(scopes[0][0]) <= {"process_manage", "todo_list"}


def test_unknown_toolset_and_auxiliary_path_are_sticky_incomplete():
    from agent.tool_diagnostic import current_tool_send_observer
    from agent.tool_diagnostic_transport import (
        bind_agent_tool_scope,
        mark_auxiliary_send,
    )

    observer = ToolSendObserver("run_x", "builder", "owner", 123, 456)
    observer.set_tool_scope((), (), False)
    agent = SimpleNamespace(
        tools=[],
        enabled_toolsets=["terminal", "plugins"],
        api_mode="chat_completions",
        provider="nous",
    )
    bind_agent_tool_scope(agent, observer)
    token = current_tool_send_observer.set(observer)
    try:
        mark_auxiliary_send()
    finally:
        current_tool_send_observer.reset(token)
    observer.capture_sdk_send(
        "main",
        "chat_completions",
        "main",
        [],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.close_producer()
    assert observer.snapshot()["state"] == "incomplete"
    assert observer.snapshot()["reason"] == "unsupported_configuration"
    auxiliary = ToolSendObserver("run_y", "builder", "owner", 123, 456)
    token = current_tool_send_observer.set(auxiliary)
    try:
        mark_auxiliary_send()
    finally:
        current_tool_send_observer.reset(token)
    auxiliary.capture_sdk_send(
        "main",
        "chat_completions",
        "main",
        [],
        deferred_tool_names=(),
        tool_search_active=False,
    )
    auxiliary.close_producer()
    assert auxiliary.snapshot()["reason"] == "unsupported_call_role"


def test_no_mcp_config_sentinel_is_removed_before_agent_scope(monkeypatch, tmp_path):
    from hermes_cli.tools_config import _get_platform_tools

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    resolved = _get_platform_tools(
        {"platform_toolsets": {"api_server": ["terminal", "file", "todo", "no_mcp"]}},
        "api_server",
    )
    assert resolved == {"terminal", "file", "todo"}


@pytest.mark.parametrize(
    "extension",
    [
        "plugin",
        "external",
        "middleware",
        "hook",
        "registration",
        "selected_tool",
        "carryover",
        "prompt_section",
        "plugin_command",
    ],
)
def test_only_reachable_extension_prevents_complete_claim(
    monkeypatch, tmp_path, extension
):
    from agent.tool_diagnostic_transport import bind_agent_tool_scope
    from tools.registry import registry

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    bundled_path = Path(__file__).resolve().parents[2] / "plugins/platforms/raft"
    manager = SimpleNamespace(
        _plugins={
            "custom": SimpleNamespace(
                enabled=True,
                manifest=SimpleNamespace(
                    source="user" if extension == "external" else "bundled",
                    path=str(tmp_path)
                    if extension == "external"
                    else str(bundled_path),
                ),
            )
        }
        if extension in {"plugin", "external"}
        else {},
        _middleware={"llm_request": [object()]} if extension == "middleware" else {},
        _hooks={"pre_tool_call": [object()]} if extension == "hook" else {},
        _plugin_tool_names={"custom_tool"}
        if extension in {"registration", "selected_tool"}
        else set(),
        _persistent_carryover=[object()] if extension == "carryover" else [],
        _system_prompt_sections={"custom": object()}
        if extension == "prompt_section"
        else {},
        _plugin_commands={"custom": object()} if extension == "plugin_command" else {},
    )
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    observer = ToolSendObserver("run_extension", "builder", "owner", 123, 456)
    observer.set_tool_scope((), (), False)
    agent = SimpleNamespace(
        tools=[_tool("custom_tool")] if extension == "selected_tool" else [],
        enabled_toolsets=["terminal", "file", "todo"],
        api_mode="chat_completions",
        provider="nous",
        base_url="https://example.invalid/v1",
        _tool_snapshot_generation=registry._generation,
    )
    bind_agent_tool_scope(agent, observer)
    observer.capture_sdk_send(
        "main",
        "chat_completions",
        "main",
        agent.tools,
        deferred_tool_names=(),
        tool_search_active=False,
    )
    observer.close_producer()
    if extension in {
        "external",
        "middleware",
        "hook",
        "selected_tool",
        "carryover",
        "prompt_section",
        "plugin_command",
    }:
        assert observer.snapshot()["reason"] == "unsupported_configuration"
    else:
        assert observer.snapshot()["state"] == "complete"


def test_only_exact_stock_raft_activity_hooks_are_exempt(monkeypatch):
    from agent.tool_diagnostic_transport import _RAFT_HOOK_FUNCTIONS, _extensions_active

    raft = importlib.import_module("plugins.platforms.raft.adapter")
    stock = {
        kind: [getattr(raft, function_name)]
        for kind, function_name in _RAFT_HOOK_FUNCTIONS.items()
    }
    manager = SimpleNamespace(
        _plugins={},
        _middleware={},
        _hooks=stock,
        _aux_tasks={},
        _context_engine=None,
        _subscriptions={},
        _plugin_tool_names=set(),
    )
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    assert _extensions_active(set()) is False

    manager._hooks = {**stock, "pre_llm_call": [lambda **_kw: None]}
    assert _extensions_active(set()) is True
    manager._hooks = {**stock, "pre_api_request": [raft._on_session_start]}
    assert _extensions_active(set()) is True
    forged = lambda **_kw: None
    forged.__module__ = raft.__name__
    manager._hooks = {**stock, "pre_llm_call": [forged]}
    assert _extensions_active(set()) is True


def test_only_stock_gateway_owned_message_injector_is_exempt(monkeypatch, tmp_path):
    from agent.tool_diagnostic_transport import _extensions_active
    from gateway.run import GatewayRunner
    from hermes_cli.plugins import PluginManager

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    manager = PluginManager()
    runner = object.__new__(GatewayRunner)
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)

    runner._install_plugin_message_injector()
    assert _extensions_active(set()) is False

    manager.set_gateway_message_injector(runner, lambda **_kwargs: True)
    assert _extensions_active(set()) is True

    manager.set_gateway_message_injector(
        object(), runner._schedule_plugin_message_injection
    )
    assert _extensions_active(set()) is True
