"""A protected physical send receives one durable, retryable usage acknowledgement."""

from __future__ import annotations

from tests.recovery_provider_fixture import provider_admission

from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

import pytest
from openai._models import construct_type
from openai.types.completion_usage import CompletionUsage

from agent import turn_usage, usage_pricing
from agent.recovery_context import (
    bind_write_permit,
    current_incarnation,
    issue_producer_permit,
    issue_usage_write_permit,
    issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry, SendOutcome
from agent.turn_response_check import _settle_rejected_protected_send
from agent.session_persistence import _db_flush_write
from agent.context_compressor import _DB_PERSISTED_MARKER
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
from hermes_state_usage import UsageDelta
from hermes_state_recovery_message_result import prepare_message_batch


def _protected_usage_case(tmp_path: Path, monkeypatch, *, model: str, usage: CompletionUsage):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "usage-session")
    admitted = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(
            scope, "byf-recovery-v1:usage", "a" * 64, "usage-run",
            current_incarnation(), provider_admission(scope.session_id),
        ),
    )
    registry = ProducerRegistry(
        store, scope, "usage-run", 0, issue_producer_permit(store, admitted.handoff)
    )
    writer = issue_write_permit(registry.permit, store, scope, "usage-run", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")
    response = SimpleNamespace(id="scratch-response", usage=usage)

    def physical() -> None:
        send = registry.sends.begin(registry.permit, "usage-send")
        send.invoke(lambda: None)
        registry.bind_response_send(response, send)

    registry.enter(registry.permit, "sdk").run(physical)
    monkeypatch.setattr(turn_usage, "calibrate_from_usage", lambda *_: None)
    monkeypatch.setattr(turn_usage, "capture_usage_anchor", lambda *_: None)
    agent = SimpleNamespace(
        _recovery_registry=registry,
        context_compressor=SimpleNamespace(update_from_response=lambda _: None, threshold_tokens=0),
        client=None, provider="openai-api", api_mode="chat_completions", model=model,
        base_url="https://api.openai.com/v1", api_key="SCRATCH_ONLY",
        session_id=scope.session_id, _session_db=db, _session_db_created=True,
        _recovery_write_permit=writer, session_api_calls=0, session_prompt_tokens=0,
        session_completion_tokens=0, session_total_tokens=0, session_input_tokens=0,
        session_output_tokens=0, session_cache_read_tokens=0, session_cache_write_tokens=0,
        session_reasoning_tokens=0, session_estimated_cost_usd=0.0, verbose_logging=False,
        quiet_mode=True,
    )
    return db, store, scope, agent, response


@pytest.mark.parametrize(
    "raw_usage",
    [
        {"total_tokens": 1},
        {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 6},
        {"prompt_tokens": "2", "completion_tokens": 3, "total_tokens": 5},
        {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5,
         "prompt_tokens_details": {"cached_tokens": 5}},
        {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5,
         "completion_tokens_details": {"reasoning_tokens": -1}},
    ],
)
def test_protected_partial_or_invalid_native_usage_stays_unknown(
    tmp_path: Path, monkeypatch, raw_usage: dict[str, object]
) -> None:
    usage = construct_type(value=raw_usage, type_=CompletionUsage)
    db, store, scope, agent, response = _protected_usage_case(
        tmp_path, monkeypatch, model="gpt-4.1", usage=usage
    )
    try:
        turn_usage.record_response_usage(
            agent, response, messages=[], api_call_count=1, api_duration=0.1,
            compression_attempts=0, max_compression_attempts=1,
        )
        assert store.send_inventory(scope, "usage-run")[0][2] == "unknown"
        assert db._read_one("SELECT 1 FROM session_model_usage WHERE session_id=?", (scope.session_id,)) is None
    finally:
        db.close()


def test_protected_native_zero_usage_is_accounted(tmp_path: Path, monkeypatch) -> None:
    usage = CompletionUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
    db, store, scope, agent, response = _protected_usage_case(
        tmp_path, monkeypatch, model="gpt-4.1", usage=usage
    )
    try:
        turn_usage.record_response_usage(
            agent, response, messages=[], api_call_count=1, api_duration=0.1,
            compression_attempts=0, max_compression_attempts=1,
        )
        assert store.send_inventory(scope, "usage-run")[0][2] == "accounted"
        row = db._read_one(
            "SELECT input_tokens,output_tokens,api_call_count FROM session_model_usage "
            "WHERE session_id=? AND model=?", (scope.session_id, "gpt-4.1"),
        )
        assert row is not None and tuple(row) == (0, 0, 1)
    finally:
        db.close()


def test_protected_native_cache_and_reasoning_usage_is_accounted(
    tmp_path: Path, monkeypatch
) -> None:
    usage = construct_type(
        value={
            "prompt_tokens": 10,
            "completion_tokens": 4,
            "total_tokens": 14,
            "prompt_tokens_details": {"cached_tokens": 2, "cache_write_tokens": 1},
            "completion_tokens_details": {"reasoning_tokens": 2},
        },
        type_=CompletionUsage,
    )
    db, store, scope, agent, response = _protected_usage_case(
        tmp_path, monkeypatch, model="gpt-4.1", usage=usage
    )
    try:
        turn_usage.record_response_usage(
            agent, response, messages=[], api_call_count=1, api_duration=0.1,
            compression_attempts=0, max_compression_attempts=1,
        )
        assert store.send_inventory(scope, "usage-run")[0][2] == "accounted"
        row = db._read_one(
            "SELECT input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,"
            "reasoning_tokens,api_call_count FROM session_model_usage "
            "WHERE session_id=? AND model=?", (scope.session_id, "gpt-4.1"),
        )
        assert row is not None and tuple(row) == (7, 4, 2, 1, 2, 1)
    finally:
        db.close()


def test_protected_unknown_price_never_fetches_endpoint_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    usage = CompletionUsage(prompt_tokens=2, completion_tokens=3, total_tokens=5)
    db, store, scope, agent, response = _protected_usage_case(
        tmp_path, monkeypatch, model="new-unpriced-model", usage=usage
    )
    calls: list[str] = []
    monkeypatch.setattr(
        usage_pricing, "fetch_endpoint_model_metadata",
        lambda base_url, api_key="": calls.append(base_url) or {},
    )
    try:
        turn_usage.record_response_usage(
            agent, response, messages=[], api_call_count=1, api_duration=0.1,
            compression_attempts=0, max_compression_attempts=1,
        )
        assert calls == []
        assert store.send_inventory(scope, "usage-run")[0][2] == "accounted"
        row = db._read_one(
            "SELECT payload_json FROM recovery_usage_slots WHERE delta_id=?",
            ("usage-send:usage",),
        )
        assert row is not None and b'"estimated_cost_usd":null' in row[0]
    finally:
        db.close()


def test_queued_usage_applies_once_and_ack_survives_reopen(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    db = SessionDB(path)
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )
    writer = issue_write_permit(registry.permit, store, scope, "root", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")

    def _send_and_account() -> None:
        send = registry.sends.begin(registry.permit, "attempt-1")
        send.invoke(lambda: None)
        usage_writer = issue_usage_write_permit(store, send.completion)
        delta = UsageDelta(
            write_id=send.delta_id,
            attempt_id=send.attempt_id,
            generation=0,
            model="model-x",
            billing_provider="provider-x",
            input_tokens=7,
            output_tokens=3,
            estimated_cost_usd=0.25,
            api_call_count=1,
        )
        assert db.queue_recovery_usage(usage_writer, delta) == send.delta_id
        ack = db.wait_recovery_write_ack(scope, send.delta_id, timeout=5)
        assert ack.state == "committed"
        assert db.queue_recovery_usage(usage_writer, delta) == send.delta_id
        with pytest.raises(RecoveryRefused):
            db.queue_recovery_usage(
                usage_writer,
                UsageDelta(
                    write_id=send.delta_id,
                    attempt_id=send.attempt_id,
                    generation=0,
                    model="model-x",
                    billing_provider="provider-x",
                    input_tokens=8,
                    output_tokens=3,
                    estimated_cost_usd=0.25,
                    api_call_count=1,
                ),
            )
        send.finish(
            SendOutcome(
                kind="accounted",
                attempt_id=send.attempt_id,
                acknowledged_delta_ids=(send.delta_id,),
            )
        )

    try:
        registry.enter(registry.permit, "sdk").run(_send_and_account)
        row = db._read_one(
            "SELECT input_tokens,output_tokens,api_call_count,model,billing_provider "
            "FROM sessions WHERE id=?",
            (scope.session_id,),
        )
        assert tuple(row) == (7, 3, 1, "model-x", "provider-x")
        model_row = db._read_one(
            "SELECT input_tokens,output_tokens,api_call_count FROM session_model_usage "
            "WHERE session_id=? AND model=?",
            (scope.session_id, "model-x"),
        )
        assert tuple(model_row) == (7, 3, 1)
        with pytest.raises(sqlite3.DatabaseError):
            db._write_sql(
                "DELETE FROM session_model_usage WHERE session_id=?",
                (scope.session_id,),
            )
    finally:
        db.close()
    reopened = SessionDB(path)
    try:
        assert reopened.read_write_ack(scope, "attempt-1:usage").state == "committed"
    finally:
        reopened.close()


def test_failed_protected_apply_stays_failed_after_legacy_flush(
    tmp_path: Path, monkeypatch
) -> None:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "missing-session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )
    original_apply = RecoveryStore.apply_usage_delta

    def fail_exact_usage(self, permit, delta, digest):
        if delta.write_id == "attempt-failed:usage":
            raise RecoveryRefused("scratch_usage_apply_failure")
        return original_apply(self, permit, delta, digest)

    monkeypatch.setattr(RecoveryStore, "apply_usage_delta", fail_exact_usage)

    def _failed_accounting() -> None:
        send = registry.sends.begin(registry.permit, "attempt-failed")
        send.invoke(lambda: None)
        writer = issue_usage_write_permit(store, send.completion)
        delta = UsageDelta(
            write_id=send.delta_id,
            attempt_id=send.attempt_id,
            generation=0,
            model="model-x",
            billing_provider="provider-x",
            input_tokens=5,
        )
        db.queue_recovery_usage(writer, delta)
        assert (
            db.wait_recovery_write_ack(scope, send.delta_id, timeout=5).state
            == "failed"
        )
        with pytest.raises(RecoveryRefused):
            db.queue_recovery_usage(writer, delta)
        send.finish(
            SendOutcome(
                kind="unknown",
                attempt_id=send.attempt_id,
                reason="usage_ack_failed",
            )
        )

    try:
        registry.enter(registry.permit, "sdk").run(_failed_accounting)
        db.queue_token_counts(
            "ordinary", input_tokens=2, model="model-x", api_call_count=1
        )
        assert db.flush_token_counts(timeout=5)
        assert db.read_write_ack(scope, "attempt-failed:usage").state == "failed"
        reasons = db._read_one(
            "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
            (scope.session_id,),
        )[0]
        assert "failed_usage_acknowledgement" in reasons
    finally:
        db.close()


def test_rejected_response_consumes_exact_send_before_retry(tmp_path: Path) -> None:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )

    def _reject() -> None:
        send = registry.sends.begin(registry.permit, "attempt-rejected")
        response = send.invoke(lambda: SimpleNamespace())
        registry.bind_response_send(response, send)
        _settle_rejected_protected_send(
            SimpleNamespace(_recovery_registry=registry), response
        )
        assert store.send_inventory(scope, "root")[0][2] == "unknown"

    try:
        registry.enter(registry.permit, "sdk").run(_reject)
        reasons = db._read_one(
            "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
            (scope.session_id,),
        )[0]
        assert "unknown_send_outcome" in reasons
    finally:
        db.close()


def test_queued_usage_finishes_after_sdk_worker_and_close_request(
    tmp_path: Path,
) -> None:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )
    writer = issue_write_permit(registry.permit, store, scope, "root", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")

    def _physical_return():
        send = registry.sends.begin(registry.permit, "attempt-late")
        response = send.invoke(lambda: SimpleNamespace())
        registry.bind_response_send(response, send)
        return response

    try:
        response = registry.enter(registry.permit, "sdk").run(_physical_return)
        assert store.send_inventory(scope, "root")[0][2] == "invoking"
        store.begin_close(
            scope,
            SealRequest(
                request_id=str(uuid4()),
                session_id=scope.session_id,
                run_ids=["root"],
                expected_membership_sha256=membership_sha256(["root"]),
            ),
        )
        send = registry.claim_response_send(response)
        usage_writer = issue_usage_write_permit(store, send.completion)
        delta = UsageDelta(
            write_id=send.delta_id,
            attempt_id=send.attempt_id,
            generation=0,
            model="model-x",
            billing_provider="provider-x",
            input_tokens=2,
        )
        db.queue_recovery_usage(usage_writer, delta)
        assert (
            db.wait_recovery_write_ack(scope, send.delta_id, timeout=5).state
            == "committed"
        )
        send.finish(
            SendOutcome(
                kind="accounted",
                attempt_id=send.attempt_id,
                acknowledged_delta_ids=(send.delta_id,),
            )
        )
        assert db.get_session(scope.session_id)["input_tokens"] == 2
    finally:
        db.close()


def test_transcript_commit_lost_response_reads_ack_before_stamping_markers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), provider_admission(scope.session_id)
        ),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )
    writer = issue_write_permit(registry.permit, store, scope, "root", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")
    agent = SimpleNamespace(
        _session_db=db,
        session_id=scope.session_id,
        _recovery_registry=registry,
        _recovery_write_permit=writer,
    )
    row = {"role": "user", "content": "durable"}
    live = {"role": "user", "content": "durable"}
    append = db.append_messages_batch

    def _fail_before_effect(**_kwargs):
        raise RuntimeError("before effect")

    monkeypatch.setattr(db, "append_messages_batch", _fail_before_effect)
    with pytest.raises(RuntimeError, match="before effect"):
        _db_flush_write(agent, [row], [live])
    pending = agent._recovery_pending_message_batch
    assert pending[4].matches_input([row])
    row["_row_id"] = 42
    with pytest.raises(RecoveryRefused, match="write_payload_conflict"):
        _db_flush_write(agent, [row], [live])
    assert agent._recovery_pending_message_batch is pending
    row.pop("_row_id")

    def _commit_then_lose_response(**kwargs):
        append(**kwargs)
        # The permit's issued identity survives producer closure for exact
        # acknowledgement readback after the physical write finished.
        store.close_producer(scope, "root", registry.permit)
        raise RuntimeError("response lost after commit")

    monkeypatch.setattr(db, "append_messages_batch", _commit_then_lose_response)
    try:
        _db_flush_write(agent, [row], [live])
        assert len(db.get_messages(scope.session_id)) == 1
        assert live[_DB_PERSISTED_MARKER] is True
        assert row["_row_id"] == live["_row_id"] == db.get_messages(scope.session_id)[0]["id"]
        assert agent._recovery_pending_message_batch is None
    finally:
        db.close()


def test_nudge_cannot_hydrate_root_message_ack_after_pre_effect_failure(
    tmp_path: Path, monkeypatch,
) -> None:
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "session")
    root = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "root",
                          current_incarnation(), provider_admission(scope.session_id)),
    )
    root_registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, root.handoff))
    root_writer = issue_write_permit(root_registry.permit, store, scope, "root", 0)
    with bind_write_permit(root_writer):
        db.create_session(scope.session_id, "api_server")
    row = {"role": "user", "content": "identical"}
    prepared = prepare_message_batch([row])
    try:
        db.append_messages_batch(
            scope.session_id, [dict(row)], recovery_permit=root_writer,
            recovery_write_id="root-message", recovery_payload_sha256=prepared.payload_sha256)
        store.close_producer(scope, "root", root_registry.permit)
        nudge = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=1,
                              parent_run_id="root"),
            AdmissionIdentity(scope, "byf-recovery-v1:nudge", "c" * 64, "nudge",
                              current_incarnation(), provider_admission(scope.session_id)),
        )
        assert nudge.outcome == "created"
        nudge_registry = ProducerRegistry(
            store, scope, "nudge", 1, issue_producer_permit(store, nudge.handoff))
        nudge_writer = issue_write_permit(nudge_registry.permit, store, scope, "nudge", 1)
        live = dict(row)
        agent = SimpleNamespace(
            _session_db=db, session_id=scope.session_id,
            _recovery_registry=nudge_registry, _recovery_write_permit=nudge_writer,
            _recovery_pending_message_batch=(scope, "nudge", 1, "root-message", prepared),
        )

        def _pre_effect_failure(**_kwargs):
            raise RuntimeError("nudge append never entered guarded write")

        monkeypatch.setattr(db, "append_messages_batch", _pre_effect_failure)
        with pytest.raises((RuntimeError, RecoveryRefused)):
            _db_flush_write(agent, [row], [live])
        assert "_row_id" not in row and "_row_id" not in live
        assert _DB_PERSISTED_MARKER not in live
        assert agent._recovery_pending_message_batch is not None
        assert len(db.get_messages(scope.session_id)) == 1
    finally:
        db.close()
