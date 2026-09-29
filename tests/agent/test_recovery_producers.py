"""Durable protected-producer and physical-send boundaries."""

from __future__ import annotations

from tests.recovery_provider_fixture import provider_admission

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread
from uuid import uuid4

import pytest

from agent.recovery_context import (
    current_incarnation,
    issue_producer_permit,
    issue_usage_write_permit,
    usage_write_binding,
)
from agent.recovery_producers import ProducerRegistry, SendOutcome
from gateway.platforms.api_server_recovery_contract import (
    RecoveryAdmission,
    SealRequest,
)
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
    membership_sha256,
)


def _admitted(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "run_root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    assert admitted.outcome == "created"
    registry = ProducerRegistry(
        store, scope, "run_root", 0, issue_producer_permit(store, admitted.handoff)
    )
    return db, store, scope, registry


def _closing(store: RecoveryStore, scope: RecoveryScope):
    return store.begin_close(
        scope,
        SealRequest(
            request_id=str(uuid4()),
            session_id=scope.session_id,
            run_ids=["run_root"],
            expected_membership_sha256=membership_sha256(["run_root"]),
        ),
    )


def test_cancelled_future_is_not_closed(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    try:
        lease = registry.enter(registry.permit, "executor")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(lease.run, lambda: (entered.set(), release.wait()))
            assert entered.wait(5)
            assert not future.cancel()
            registry.request_close()
            assert _closing(store, scope).members[0].producer_state == "open"
            release.set()
            future.result(timeout=5)
        assert (
            store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
        )
    finally:
        release.set()
        db.close()


def test_queued_tool_cancel_before_start(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    entered, release, ran = Event(), Event(), Event()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = registry.enter(registry.permit, "tool")
            second = registry.enter(registry.permit, "tool")
            running = pool.submit(first.run, lambda: (entered.set(), release.wait()))
            assert entered.wait(5)
            queued = pool.submit(second.run, ran.set)
            assert queued.cancel()
            second.cancel_before_start()
            registry.request_close()
            assert _closing(store, scope).members[0].producer_state == "open"
            release.set()
            running.result(timeout=5)
        assert not ran.is_set()
        assert (
            store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
        )
    finally:
        release.set()
        db.close()


def test_tool_timeout_retains_worker(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    try:
        lease = registry.enter(registry.permit, "tool")
        worker = Thread(
            target=lambda: lease.run(lambda: (entered.set(), release.wait()))
        )
        worker.start()
        assert entered.wait(5)
        with pytest.raises(RecoveryRefused):
            lease.cancel_before_start()
        registry.request_close()
        assert _closing(store, scope).members[0].producer_state == "open"
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert (
            store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
        )
    finally:
        release.set()
        db.close()


def test_send_begin_close_create_is_admitted_but_retry_refused(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    invoked = []
    try:
        sdk = registry.enter(registry.permit, "sdk")

        def send():
            permit = registry.sends.begin(registry.permit, "physical-one")
            registry.request_close()
            assert _closing(store, scope).members[0].producer_state == "open"
            assert permit.invoke(lambda: invoked.append("once")) is None
            with pytest.raises(RecoveryRefused):
                permit.invoke(lambda: invoked.append("twice"))
            with pytest.raises(RecoveryRefused):
                registry.sends.begin(registry.permit, "physical-two")
            registry.sends.finish(
                permit,
                SendOutcome(
                    kind="unknown",
                    attempt_id="physical-one",
                    reason="usage_unavailable",
                ),
            )

        sdk.run(send)
        assert invoked == ["once"]
        assert store.lookup_root(scope, "run_root").state == "unsupported"
    finally:
        db.close()


def test_no_call_requires_empty_durable_send_ledger(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    try:
        assert store.send_inventory(scope, "run_root") == ()
        sdk = registry.enter(registry.permit, "sdk")

        def reserved_only():
            permit = registry.sends.begin(registry.permit, "cancelled-before-sdk")
            assert len(store.send_inventory(scope, "run_root")) == 1
            registry.sends.finish(
                permit,
                SendOutcome(
                    kind="no_charge_proved",
                    attempt_id="cancelled-before-sdk",
                    reason="sdk_not_entered",
                ),
            )

        sdk.run(reserved_only)
        registry.request_close()
        assert _closing(store, scope).members[0].producer_state == "closed"
        assert len(store.send_inventory(scope, "run_root")) == 1
    finally:
        db.close()


def test_usage_completion_is_one_use_and_response_binding_is_exact(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    response = object()
    try:
        sdk = registry.enter(registry.permit, "sdk")

        def send():
            permit = registry.sends.begin(registry.permit, "physical-response")
            permit.invoke(lambda: response)
            registry.bind_response_send(response, permit)

        sdk.run(send)
        claimed = registry.claim_response_send(response)
        assert claimed is not None
        assert registry.claim_response_send(response) is None
        write = issue_usage_write_permit(store, claimed.completion)
        binding = usage_write_binding(write, store)
        assert binding is not None
        assert (
            binding.scope,
            binding.run_id,
            binding.generation,
            binding.producer_id,
            binding.attempt_id,
            binding.delta_id,
            binding.mutation,
        ) == (
            scope,
            "run_root",
            0,
            sdk.producer_id,
            "physical-response",
            "physical-response:usage",
            "usage",
        )
        with pytest.raises(RecoveryRefused):
            issue_usage_write_permit(store, claimed.completion)
        with pytest.raises(RecoveryRefused) as unacked:
            claimed.finish(
                SendOutcome(
                    kind="accounted",
                    attempt_id=claimed.attempt_id,
                    acknowledged_delta_ids=(claimed.delta_id,),
                )
            )
        assert unacked.value.code == "usage_ack_required"
        claimed.finish(
            SendOutcome(
                kind="unknown",
                attempt_id=claimed.attempt_id,
                reason="usage_unavailable",
            )
        )
        registry.request_close()
        assert _closing(store, scope).state == "unsupported"
    finally:
        db.close()


@pytest.mark.parametrize("legacy", ["close", "incomplete"])
def test_legacy_member_settlement_waits_for_active_child(tmp_path: Path, legacy: str):
    db, store, scope, registry = _admitted(tmp_path)
    entered, release = Event(), Event()
    try:
        child = registry.enter(registry.permit, "tool")
        worker = Thread(target=lambda: child.run(lambda: (entered.set(), release.wait())))
        worker.start()
        assert entered.wait(5)
        if legacy == "close":
            store.close_producer(scope, "run_root", registry.permit)
        else:
            store.mark_incomplete(scope, "run_root", registry.permit, "untracked_producer")
        view = _closing(store, scope)
        assert view.members[0].producer_state == "open"
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        view = store.lookup_root(scope, "run_root")
        assert view.members[0].producer_state == ("closed" if legacy == "close" else "incomplete")
    finally:
        release.set()
        db.close()


def test_active_parent_can_admit_exact_callback_during_closing(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    entered, proceed, callback_done = Event(), Event(), Event()
    errors: list[BaseException] = []
    try:
        parent = registry.enter(registry.permit, "executor")

        def parent_body():
            entered.set()
            assert proceed.wait(5)
            child = registry.enter(parent, "callback")
            child.run(callback_done.set)

        def worker_body():
            try:
                parent.run(parent_body)
            except BaseException as exc:
                errors.append(exc)

        worker = Thread(target=worker_body)
        worker.start()
        assert entered.wait(5)
        assert _closing(store, scope).members[0].producer_state == "open"
        for parent_candidate, kind in ((registry.permit, "callback"), (parent, "tool"), (parent, "sdk")):
            with pytest.raises(RecoveryRefused):
                registry.enter(parent_candidate, kind)
        proceed.set()
        worker.join(5)
        assert not worker.is_alive() and not errors and callback_done.is_set()
        rows = db._read_one("SELECT parent_producer_id FROM recovery_producers WHERE kind='callback'")
        assert rows is not None and rows[0] == parent.producer_id
        registry.request_close()
        assert store.lookup_root(scope, "run_root").members[0].producer_state == "closed"
        with pytest.raises(RecoveryRefused):
            registry.enter(parent, "callback")
    finally:
        proceed.set()
        db.close()


def test_same_response_cannot_rebind_to_second_send(tmp_path: Path):
    db, store, _scope, registry = _admitted(tmp_path)
    response = object()
    try:
        sdk = registry.enter(registry.permit, "sdk")

        def body():
            first = registry.sends.begin(registry.permit, "first")
            second = registry.sends.begin(registry.permit, "second")
            first.invoke(lambda: response)
            second.invoke(lambda: response)
            registry.bind_response_send(response, first)
            registry.bind_response_send(response, first)
            with pytest.raises(RecoveryRefused):
                registry.bind_response_send(response, second)
            assert registry.claim_response_send(response) is first
            for send in (first, second):
                send.finish(SendOutcome(kind="unknown", attempt_id=send.attempt_id,
                                        reason="usage_unavailable"))

        sdk.run(body)
    finally:
        db.close()


def test_legacy_close_waits_for_preexisting_send_and_usage_slot(tmp_path: Path):
    db, store, scope, registry = _admitted(tmp_path)
    try:
        sdk = registry.enter(registry.permit, "sdk")
        sends = []

        def body():
            send = registry.sends.begin(registry.permit, "awaiting-usage")
            send.invoke(lambda: object())
            sends.append(send)

        sdk.run(body)
        store.close_producer(scope, "run_root", registry.permit)
        assert _closing(store, scope).members[0].producer_state == "open"
        sends[0].finish(SendOutcome(kind="unknown", attempt_id="awaiting-usage",
                                    reason="usage_unavailable"))
        view = store.lookup_root(scope, "run_root")
        assert view.members[0].producer_state == "incomplete"
        assert view.state == "unsupported"
    finally:
        db.close()
