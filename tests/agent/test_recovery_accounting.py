"""A protected physical send receives one durable, retryable usage acknowledgement."""

from __future__ import annotations

from tests.recovery_provider_fixture import provider_admission

from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

import pytest

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


def test_failed_protected_apply_stays_failed_after_legacy_flush(tmp_path: Path) -> None:
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
    assert pending[2].matches_input([row])
    row["_row_id"] = 42
    with pytest.raises(RecoveryRefused, match="write_payload_conflict"):
        _db_flush_write(agent, [row], [live])
    assert agent._recovery_pending_message_batch is pending
    row.pop("_row_id")

    def _commit_then_lose_response(**kwargs):
        append(**kwargs)
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
