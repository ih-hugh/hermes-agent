"""Physical SDK and callback runtime paths for protected runs."""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent.recovery_context import (
    bind_write_permit, current_incarnation, issue_producer_permit,
    issue_usage_write_permit, issue_write_permit,
)
from agent.recovery_producers import (
    ProducerRegistry,
    SendOutcome,
    begin_chat_send,
    finish_unknown_if_active,
)
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore, membership_sha256
from hermes_state_usage import UsageDelta


def _admitted(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    result = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "run_root", current_incarnation()),
    )
    registry = ProducerRegistry(
        store, scope, "run_root", 0, issue_producer_permit(store, result.handoff))
    return db, store, scope, registry


def _close(store: RecoveryStore, scope: RecoveryScope):
    return store.begin_close(scope, SealRequest(
        request_id=str(uuid4()), session_id=scope.session_id, run_ids=["run_root"],
        expected_membership_sha256=membership_sha256(["run_root"])))


def test_nonstream_create_records_exact_send_and_response(tmp_path: Path, monkeypatch):
    from openai import OpenAI
    from agent import chat_completion_helpers as helpers
    from agent import tool_diagnostic_transport

    db, store, scope, registry = _admitted(tmp_path)
    response = object()
    client = OpenAI(api_key="test", max_retries=0)
    monkeypatch.setattr(client.chat.completions, "create", lambda **kw: response)
    agent = SimpleNamespace(api_mode="chat_completions", provider="openai",
                            is_subagent=False, _fallback_index=0,
                            enabled_toolsets=["terminal"])
    monkeypatch.setattr(tool_diagnostic_transport, "observe_sdk_send", lambda *_: None)
    try:
        sdk = registry.enter(registry.permit, "sdk")
        sdk.run(lambda: helpers._dispatch_nonstreaming_api_request(
            agent, {"model": "test"}, make_client=lambda *_: client))
        assert len(store.send_inventory(scope, "run_root")) == 1
        send = registry.claim_response_send(response)
        assert send is not None and registry.claim_response_send(response) is None
        send.finish(SendOutcome(kind="unknown", attempt_id=send.attempt_id,
                                reason="usage_unavailable"))
        registry.request_close()
        assert _close(store, scope).state == "unsupported"
    finally:
        client.close()
        db.close()


def test_actual_nonstream_return_then_close_queues_exact_usage_ack(tmp_path: Path, monkeypatch):
    from openai import OpenAI
    from agent import chat_completion_helpers as helpers
    from agent import tool_diagnostic_transport

    db, store, scope, registry = _admitted(tmp_path)
    client = OpenAI(api_key="test", max_retries=0)
    response = SimpleNamespace(id="response", usage=SimpleNamespace(prompt_tokens=2, completion_tokens=3))
    monkeypatch.setattr(client.chat.completions, "create", lambda **kw: response)
    monkeypatch.setattr(tool_diagnostic_transport, "observe_sdk_send", lambda *_: None)
    agent = SimpleNamespace(api_mode="chat_completions", provider="openai",
                            is_subagent=False, _fallback_index=0,
                            enabled_toolsets=["terminal"])
    writer = issue_write_permit(
        registry.permit, store, scope, registry.run_id, registry.generation)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")
    try:
        sdk = registry.enter(registry.permit, "sdk")
        actual = sdk.run(lambda: helpers._dispatch_nonstreaming_api_request(
            agent, {"model": "test"}, make_client=lambda *_: client))
        assert actual is response
        assert store.send_inventory(scope, "run_root")[0][2] == "invoking"
        assert _close(store, scope).members[0].producer_state == "open"
        send = registry.claim_response_send(response)
        assert send is not None
        usage_writer = issue_usage_write_permit(store, send.completion)
        delta = UsageDelta(
            write_id=send.delta_id, attempt_id=send.attempt_id,
            generation=registry.generation, model="test", billing_provider="openai",
            input_tokens=2, output_tokens=3, api_call_count=1)
        db.queue_recovery_usage(usage_writer, delta)
        assert db.wait_recovery_write_ack(scope, send.delta_id, timeout=5).state == "committed"
        send.finish(SendOutcome(
            kind="accounted", attempt_id=send.attempt_id,
            acknowledged_delta_ids=(send.delta_id,)))
        registry.request_close()
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
    finally:
        client.close()
        db.close()


@pytest.mark.parametrize("kind", ["nonzero", "custom", "transport"])
def test_unknown_or_nonzero_sdk_retries_refuse_before_create(tmp_path: Path, kind):
    import httpx
    from openai import OpenAI

    db, store, scope, registry = _admitted(tmp_path)
    calls = []
    if kind == "nonzero":
        client = OpenAI(api_key="test", max_retries=1)
    elif kind == "transport":
        client = OpenAI(api_key="test", max_retries=0, http_client=httpx.Client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200))))
    else:
        client = SimpleNamespace(max_retries=0, chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kw: calls.append(kw))))
    try:
        sdk = registry.enter(registry.permit, "sdk")
        def attempt():
            with pytest.raises(RecoveryRefused):
                begin_chat_send(client)
        sdk.run(attempt)
        assert not calls and not store.send_inventory(scope, "run_root")
        assert _close(store, scope).state == "unsupported"
    finally:
        if kind != "custom":
            client.close()
        db.close()


def test_stream_reopen_inventories_both_physical_sends(tmp_path: Path, monkeypatch):
    from openai import OpenAI
    from agent import chat_completion_helpers as helpers
    from agent import tool_diagnostic_transport

    db, store, scope, registry = _admitted(tmp_path)
    calls = []
    client = OpenAI(api_key="test", max_retries=0)
    monkeypatch.setattr(client.chat.completions, "create",
                        lambda **kw: calls.append(kw) or object())
    agent = SimpleNamespace(
        base_url="https://provider.invalid", provider="openai", api_mode="chat_completions",
        _stream_options_unsupported=False, _create_request_openai_client=lambda **kw: client,
        _touch_activity=lambda *_: None)
    driver = SimpleNamespace(agent=agent, clients=SimpleNamespace(set_client=lambda x: x),
                             last_chunk_time={})
    monkeypatch.setattr(tool_diagnostic_transport, "observe_sdk_send", lambda *_: None)
    try:
        sdk = registry.enter(registry.permit, "sdk")
        def attempt():
            helpers._StreamingCall._open_chat_stream(driver, {"model": "test"})
            first = driver._recovery_send
            helpers._StreamingCall._open_chat_stream(driver, {"model": "test"})
            assert driver._recovery_send is not first
            finish_unknown_if_active(driver._recovery_send, "usage_unavailable")
        sdk.run(attempt)
        assert len(calls) == len(store.send_inventory(scope, "run_root")) == 2
        registry.request_close()
        assert _close(store, scope).state == "unsupported"
    finally:
        client.close()
        db.close()


def test_active_executor_callback_runs_after_close(tmp_path: Path):
    from gateway.platforms.api_server_runs import _schedule_run_callback

    db, store, scope, registry = _admitted(tmp_path)
    entered, release, callback_done = Event(), Event(), Event()
    parent = registry.enter(registry.permit, "executor")

    async def scenario():
        loop = asyncio.get_running_loop()
        owner = SimpleNamespace(_protected_run_registries={"run_root": registry})
        def work():
            entered.set()
            assert release.wait(5)
            _schedule_run_callback(owner, "run_root", loop, callback_done.set)
        worker = Thread(target=lambda: parent.run(work))
        worker.start()
        assert await asyncio.to_thread(entered.wait, 5)
        assert _close(store, scope).members[0].producer_state == "open"
        release.set()
        assert await asyncio.to_thread(callback_done.wait, 5)
        await asyncio.to_thread(worker.join, 5)
        assert not worker.is_alive()
        registry.request_close()
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        db.close()


def test_status_barrier_closes_only_after_worker_and_ordered_write(tmp_path: Path):
    from gateway.platforms.api_server_runs import _finalize_protected_producers

    db, store, scope, registry = _admitted(tmp_path)
    entered, release, worker_done = Event(), Event(), Event()
    executor = registry.enter(registry.permit, "executor")
    barrier = registry.enter(registry.permit, "callback")

    async def scenario():
        status_release = asyncio.Event()
        status_entered = asyncio.Event()

        async def status_write():
            status_entered.set()
            await status_release.wait()

        owner = SimpleNamespace(_protected_status_tasks={"run_root": asyncio.create_task(status_write())})
        coroutine_settled = asyncio.Event()
        run = SimpleNamespace(
            run_id="run_root", recovery_registry=registry, recovery_status_barrier=barrier,
            recovery_execution_settled=worker_done,
            recovery_coroutine_settled=coroutine_settled)

        def worker_body():
            try:
                executor.run(lambda: (entered.set(), release.wait()))
            finally:
                worker_done.set()

        worker = Thread(target=worker_body)
        worker.start()
        assert await asyncio.to_thread(entered.wait, 5)
        await status_entered.wait()
        registry.request_close()
        coroutine_settled.set()
        finalizer = asyncio.create_task(_finalize_protected_producers(owner, run))
        assert _close(store, scope).members[0].producer_state == "open"
        release.set()
        assert await asyncio.to_thread(worker_done.wait, 5)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "open"
        status_release.set()
        await asyncio.wait_for(finalizer, 5)
        await asyncio.to_thread(worker.join, 5)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        db.close()


@pytest.mark.parametrize("path", ["fallback", "compression", "auxiliary"])
def test_untracked_runtime_dispatch_refuses_before_effect(tmp_path: Path, path: str):
    from agent.auxiliary_client import call_llm
    from agent.chat_completion_helpers import try_activate_fallback
    from agent.conversation_compression import compress_context

    db, store, scope, registry = _admitted(tmp_path)
    executor = registry.enter(registry.permit, "executor")
    try:
        def attempt():
            with pytest.raises(RecoveryRefused):
                if path == "fallback":
                    try_activate_fallback(SimpleNamespace())
                elif path == "compression":
                    compress_context(SimpleNamespace(), [], "")
                else:
                    call_llm(messages=[])
        executor.run(attempt)
        assert not store.send_inventory(scope, "run_root")
        assert _close(store, scope).state == "unsupported"
    finally:
        db.close()


def test_sequential_tool_timeout_retains_actual_worker(tmp_path: Path, monkeypatch):
    from agent import tool_executor

    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    monkeypatch.setattr(tool_executor, "_resolve_sequential_tool_timeout", lambda: 0.01)
    monkeypatch.setattr(tool_executor, "_poll_sequential_future",
                        lambda *a: ("timeout", None) if entered.wait(5) else pytest.fail("worker did not start"))
    monkeypatch.setattr(tool_executor, "_registered_tool_worker", lambda agent: nullcontext(1))
    monkeypatch.setattr(tool_executor, "_interrupt_worker_tids", lambda *a, **kw: None)
    monkeypatch.setattr(tool_executor, "_abandoned_sequential_result", lambda *a, **kw: "timed out")
    monkeypatch.setattr(tool_executor, "_run_agent_tool_execution_middleware",
                        lambda agent, **kw: kw["execute"](kw["function_args"]))
    agent = SimpleNamespace(_interrupt_requested=False, _touch_activity=lambda *_: None)
    executor = registry.enter(registry.permit, "executor")
    try:
        def call():
            return tool_executor._run_sequential_tool_execution_middleware(
                agent, function_name="terminal", function_args={}, effective_task_id="task",
                tool_call_id="call", execute=lambda args: (entered.set(), release.wait()))
        assert executor.run(call) == "timed out"
        assert entered.is_set()
        registry.request_close()
        assert _close(store, scope).members[0].producer_state == "open"
        release.set()
        registry.wait_until_quiescent(excluding=executor)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
    finally:
        release.set()
        db.close()


def test_streaming_caller_abandon_retains_actual_sdk_worker(tmp_path: Path, monkeypatch):
    from agent import chat_completion_helpers as helpers

    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    agent = SimpleNamespace(
        api_mode="chat_completions", provider="openai", platform="api_server",
        _interrupt_requested=False)
    driver = helpers._StreamingCall(agent, {"model": "test"}, None)
    monkeypatch.setattr(driver, "_resolve_stale_timeout", lambda: None)
    monkeypatch.setattr(driver, "_call", lambda: (entered.set(), release.wait()))
    monkeypatch.setattr(driver, "_monitor_loop", lambda: entered.wait(5))
    executor = registry.enter(registry.permit, "executor")
    try:
        assert executor.run(driver.run) is None
        registry.request_close()
        assert _close(store, scope).members[0].producer_state == "open"
        release.set()
        registry.wait_until_quiescent(excluding=executor)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
    finally:
        release.set()
        db.close()


def test_nonstream_interrupt_retains_actual_sdk_worker(tmp_path: Path, monkeypatch):
    from agent import chat_completion_helpers as helpers
    from agent.chat_completion_nonstream import _NonStreamRequest

    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    agent = SimpleNamespace(
        api_mode="chat_completions", provider="openai", _interrupt_requested=False,
        _touch_activity=lambda *_: None)
    watchdog = SimpleNamespace(codex=False, ttfb_enabled=False, idle_enabled=False,
                               stale_timeout=3600.0)
    monkeypatch.setattr(helpers, "_resolve_nonstream_watchdogs", lambda *_: watchdog)
    request = _NonStreamRequest(agent, {"model": "test"})
    monkeypatch.setattr(request, "_call", lambda: (entered.set(), release.wait()))
    monkeypatch.setattr(request, "_emit_wait_notice",
                        lambda *_args, **_kw: setattr(agent, "_interrupt_requested", entered.is_set()))
    monkeypatch.setattr(request, "_interrupt", lambda *_: (_ for _ in ()).throw(InterruptedError()))
    executor = registry.enter(registry.permit, "executor")
    try:
        with pytest.raises(InterruptedError):
            executor.run(request.run)
        registry.request_close()
        assert _close(store, scope).members[0].producer_state == "open"
        release.set()
        registry.wait_until_quiescent(excluding=executor)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
    finally:
        release.set()
        db.close()


def test_inline_watchdog_threads_have_completion_leases(tmp_path: Path):
    from agent.chat_completion_helpers import _InlineRequest

    db, store, scope, registry = _admitted(tmp_path)
    agent = SimpleNamespace(_touch_activity=lambda *_: None)
    executor = registry.enter(registry.permit, "executor")
    try:
        def body():
            request = _InlineRequest(agent, {}, 60.0, 0.0)
            request.start_watchdogs()
            registry.request_close()
            assert _close(store, scope).members[0].producer_state == "open"
            request.stop_watchdogs()
        executor.run(body)
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
    finally:
        db.close()
