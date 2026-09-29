"""Finalization commits only complete source evidence and immutable bytes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from agent.recovery_context import (
    AdmissionHandoff,
    bind_write_permit,
    current_incarnation,
    issue_producer_permit,
    issue_usage_write_permit,
    issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry, SendOutcome
from gateway.platforms.api_server_recovery_artifacts import (
    canonical_json_bytes,
)
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
    PreparedProviderEvidence,
    finalize,
    prepare_provider_evidence,
    read_seal_bytes,
    read_sealed_page_bytes,
)
import hermes_state_recovery_seal as seal_module
from hermes_state_recovery_values import SESSION_COLUMNS
from hermes_state_recovery_values import MESSAGE_COLUMNS, decode_sqlite_cells
from hermes_state_recovery_message_result import prepare_message_batch
from hermes_state_usage import UsageDelta
from tests.recovery_provider_fixture import provider_admission, selected_provider


def _case(tmp_path: Path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "seal-session")
    admission = provider_admission(scope.session_id)
    plugin = selected_provider(monkeypatch, session_id=scope.session_id)
    accepted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope,
            "byf-recovery-v1:seal-root",
            "a" * 64,
            "root",
            current_incarnation(),
            admission,
        ),
    )
    assert accepted.outcome == "created"
    assert isinstance(accepted.handoff, AdmissionHandoff)
    producer = issue_producer_permit(store, accepted.handoff)
    writer = issue_write_permit(producer, store, scope, "root", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")
    signed = SignedStatusWire.model_validate({
        "schema": "byf.signed-workspace-status/v1",
        "status": {
            "schema": "byf.workspace-status/v1",
            "reference": admission.reference.model_dump(mode="json"),
            "session_id": scope.session_id,
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
    plugin.read_recovery_binding_wire = lambda expected: (
        RecoveryProviderReadback()
        if expected == admission.canonical_bytes()
        else (_ for _ in ()).throw(AssertionError("wrong provider admission"))
    )
    evidence = prepare_provider_evidence(SelectedProviderCapture(admission, plugin))
    return db, store, scope, producer, evidence


def _close(store: RecoveryStore, scope: RecoveryScope, producer) -> SealRequest:
    _close_root(store, scope, producer)
    request = SealRequest(
        request_id=str(uuid4()),
        session_id=scope.session_id,
        run_ids=("root",),
        expected_membership_sha256=membership_sha256(("root",)),
    )
    assert store.begin_close(scope, request).phase == "closing"
    return request


def _close_root(store: RecoveryStore, scope: RecoveryScope, producer) -> None:
    store.register_producer(scope, "root", producer, "status-barrier", "callback")
    store.start_registered_producer(scope, "root", producer, "status-barrier")
    store.update_status("root", {"status": "completed"})
    store.close_registered_producer(scope, "root", producer, "status-barrier")
    store.close_producer(scope, "root", producer)


def _nudge(store: RecoveryStore, scope: RecoveryScope, admission):
    accepted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=1, parent_run_id="root"
        ),
        AdmissionIdentity(
            scope,
            "byf-recovery-v1:seal-nudge",
            "d" * 64,
            "nudge",
            current_incarnation(),
            admission,
        ),
    )
    assert accepted.outcome == "created"
    assert isinstance(accepted.handoff, AdmissionHandoff)
    return issue_producer_permit(store, accepted.handoff)


def _close_nudge(store: RecoveryStore, scope: RecoveryScope, producer) -> None:
    store.register_producer(scope, "nudge", producer, "nudge-barrier", "callback")
    store.start_registered_producer(scope, "nudge", producer, "nudge-barrier")
    store.update_status("nudge", {"status": "completed"})
    store.close_registered_producer(scope, "nudge", producer, "nudge-barrier")
    store.close_producer(scope, "nudge", producer)


def test_no_call_seal_is_immutable_across_reopen(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    reopened = None
    try:
        request = _close(store, scope, producer)
        result = finalize(store, scope, request, evidence)
        assert result.state == "sealed"
        assert result.receipt is not None
        assert result.receipt.no_calls is True
        raw = read_seal_bytes(store, scope, "root")
        first_page = read_sealed_page_bytes(store, scope, "root", 0)
        assert finalize(store, scope, request, None) == result
        assert raw == read_seal_bytes(store, scope, "root")
        db.close()
        reopened = RecoveryStore(SessionDB(tmp_path / "state.db"))
        assert read_seal_bytes(reopened, scope, "root") == raw
        assert read_sealed_page_bytes(reopened, scope, "root", 0) == first_page
        with pytest.raises(RecoveryRefused, match="seal_not_found"):
            read_seal_bytes(reopened, scope, "other-root")
    finally:
        if reopened is not None:
            reopened.db.close()
        else:
            db.close()


def test_new_process_reads_only_committed_seal_bytes(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        finalize(store, scope, request, evidence)
        expected_receipt = hashlib.sha256(
            read_seal_bytes(store, scope, "root")
        ).hexdigest()
        expected_page = hashlib.sha256(
            read_sealed_page_bytes(store, scope, "root", 0)
        ).hexdigest()
    finally:
        db.close()
    script = """
import hashlib
import sys
from pathlib import Path
from hermes_state import SessionDB
from hermes_state_recovery import RecoveryScope, RecoveryStore
from hermes_state_recovery_seal import read_seal_bytes, read_sealed_page_bytes
from agent.recovery_context import current_incarnation
db = SessionDB(Path(sys.argv[1]))
try:
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, 'factory', 'b' * 64, 'seal-session')
    print(current_incarnation())
    print(hashlib.sha256(read_seal_bytes(store, scope, 'root')).hexdigest())
    print(hashlib.sha256(read_sealed_page_bytes(store, scope, 'root', 0)).hexdigest())
finally:
    db.close()
"""
    output = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "state.db")],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()
    assert output[0] != current_incarnation()
    assert output[1:] == [expected_receipt, expected_page]


def test_incomplete_owner_refuses_without_receipt(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        store._write(
            lambda conn: conn.execute(
                "UPDATE recovery_members SET owner_incarnation='predecessor' WHERE run_id='root'"
            )
        )
        with pytest.raises(RecoveryRefused, match="lost_producer_owner"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
    finally:
        db.close()


def test_constructed_provider_evidence_cannot_authorize_seal(
    tmp_path: Path, monkeypatch
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        constructed = PreparedProviderEvidence(
            evidence.capture,
            evidence.admission,
            evidence.state,
            evidence.signed_status,
            evidence.signed_status_sha256,
            evidence.container_id,
            evidence.container_attestation_sha256,
            object(),
        )
        with pytest.raises(RecoveryRefused, match="provider_readback_unavailable"):
            finalize(store, scope, request, constructed)
        replaced = replace(evidence, signed_status_sha256="0" * 64)
        with pytest.raises(RecoveryRefused, match="provider_readback_unavailable"):
            finalize(store, scope, request, replaced)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_page_write_failure_rolls_back_receipt_and_tombstone(
    tmp_path: Path, monkeypatch
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        # A scratch-only failure fires after the receipt row, during page insert.
        store._write(
            lambda conn: conn.execute(
                "CREATE TRIGGER scratch_reject_seal_page BEFORE INSERT ON recovery_sealed_pages "
                "BEGIN SELECT RAISE(ABORT,'scratch_page_failure'); END"
            )
        )
        with pytest.raises(sqlite3.IntegrityError, match="scratch_page_failure"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_sealed_pages WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
    finally:
        db.close()


def test_accounted_send_replays_exact_source_totals(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        registry = ProducerRegistry(store, scope, "root", 0, producer)

        def _invoke():
            send = registry.sends.begin(registry.permit, "attempt-one")
            send.invoke(lambda: None)
            return send

        send = registry.enter(registry.permit, "sdk").run(_invoke)
        usage_writer = issue_usage_write_permit(store, send.completion)
        delta = UsageDelta(
            write_id=send.delta_id,
            attempt_id=send.attempt_id,
            generation=0,
            model="test-model",
            billing_provider="provider-x",
            billing_base_url=None,
            billing_mode=None,
            input_tokens=17,
            output_tokens=4,
            cache_read_tokens=3,
            cache_write_tokens=2,
            reasoning_tokens=1,
            estimated_cost_usd=0.25,
            actual_cost_usd=None,
            cost_status="estimated",
            cost_source="price-table",
            pricing_version="2026-09",
        )
        store.reserve_usage_payload(usage_writer, delta, delta.digest())
        store.apply_usage_delta(usage_writer, delta, delta.digest())
        assert (
            db._read_one(
                "SELECT COUNT(*) FROM session_model_usage WHERE session_id=?",
                (scope.session_id,),
            )[0]
            == 1
        )
        send.finish(
            SendOutcome(
                kind="accounted",
                attempt_id=send.attempt_id,
                acknowledged_delta_ids=(send.delta_id,),
            )
        )
        request = _close(store, scope, producer)
        result = finalize(store, scope, request, evidence)
        assert result.receipt is not None
        assert result.receipt.no_calls is False
        assert result.receipt.acknowledged_usage.api_call_count == 1
        assert result.receipt.acknowledged_usage.input_tokens == 17
        assert result.receipt.acknowledged_usage.billing_provider == "provider-x"
        assert result.receipt.acknowledged_usage.billing_mode is None
        assert result.receipt.send_row_count == 1
        assert result.receipt.accounting_row_count == 2
    finally:
        db.close()


def test_guarded_transcript_preserves_inactive_blob_and_json_looking_text(
    tmp_path: Path,
    monkeypatch,
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        writer = issue_write_permit(producer, store, scope, "root", 0)
        rows = [{"role": "user", "content": '{"looks":"json"}'}]
        assert (
            db.append_messages_batch(
                scope.session_id,
                rows,
                recovery_permit=writer,
                recovery_write_id="message-one",
                recovery_payload_sha256=prepare_message_batch(rows).payload_sha256,
            )
            == 1
        )
        message_id = rows[0]["_row_id"]
        assert (
            db._read_one(
                "SELECT typeof(display_identity) FROM messages WHERE id=?",
                (message_id,),
            )[0]
            == "blob"
        )
        # Scratch state models a guarded row later made inactive by transcript maintenance.
        store._write(
            lambda conn: (
                conn.execute("DROP TRIGGER recovery_guard_messages_update"),
                conn.execute("UPDATE messages SET active=0 WHERE id=?", (message_id,)),
            )
        )
        request = _close(store, scope, producer)
        result = finalize(store, scope, request, evidence)
        assert result.receipt is not None
        assert result.receipt.transcript_row_count == 1
        assert result.receipt.accounting_row_count == 2
        pages = [
            json.loads(read_sealed_page_bytes(store, scope, "root", index))
            for index in range(
                result.receipt.manifest_page_count + result.receipt.data_page_count
            )
        ]
        transcript = next(
            page["body"]["rows"][0]["value"]
            for page in pages
            if page["kind"] == "data" and page["body"]["kind"] == "transcript"
        )
        source = dict(
            zip(
                (name for name, _, _ in MESSAGE_COLUMNS),
                decode_sqlite_cells(transcript["cells"]),
                strict=True,
            )
        )
        assert source["content"] == '{"looks":"json"}'
        assert source["active"] == 0
        assert type(source["display_identity"]) is bytes
        assert transcript["lineage"] == [{"write_id": "message-one", "position": 0}]
    finally:
        db.close()


def test_closed_root_and_nudge_seal_exact_membership(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        _close_root(store, scope, producer)
        nudge = _nudge(store, scope, evidence.admission)
        _close_nudge(store, scope, nudge)
        request = SealRequest(
            request_id=str(uuid4()),
            session_id=scope.session_id,
            run_ids=("root", "nudge"),
            expected_membership_sha256=membership_sha256(("root", "nudge")),
        )
        store.begin_close(scope, request)
        result = finalize(store, scope, request, evidence)
        assert result.receipt is not None
        assert tuple(member.run_id for member in result.receipt.members) == (
            "root",
            "nudge",
        )
        assert result.receipt.no_calls is True
    finally:
        db.close()


def test_open_nudge_refuses_and_leaves_close_barrier(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        _close_root(store, scope, producer)
        _nudge(store, scope, evidence.admission)
        request = SealRequest(
            request_id=str(uuid4()),
            session_id=scope.session_id,
            run_ids=("root", "nudge"),
            expected_membership_sha256=membership_sha256(("root", "nudge")),
        )
        store.begin_close(scope, request)
        with pytest.raises(RecoveryRefused, match="lost_producer_owner"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_unexpected_member_after_close_refuses_exact_scope(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        # Only a scratch tamper can append a member after the close barrier.
        store._write(
            lambda conn: conn.execute(
                "INSERT INTO recovery_members(run_id,session_id,generation,parent_run_id,"
                "profile,scope_digest,idempotency_key,request_sha256,owner_incarnation,"
                "producer_state,status_json) "
                "SELECT 'unexpected',session_id,1,run_id,profile,scope_digest,"
                "'byf-recovery-v1:unexpected',request_sha256,owner_incarnation,"
                "'closed','{\"status\":\"completed\"}' FROM recovery_members "
                "WHERE run_id='root'"
            )
        )
        with pytest.raises(RecoveryRefused, match="missing_membership"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_unknown_send_outcome_refuses_before_seal(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        registry = ProducerRegistry(store, scope, "root", 0, producer)

        def _invoke():
            send = registry.sends.begin(registry.permit, "attempt-unknown")
            send.invoke(lambda: None)
            return send

        send = registry.enter(registry.permit, "sdk").run(_invoke)
        send.finish(
            SendOutcome(
                kind="unknown",
                attempt_id=send.attempt_id,
                reason="lost_result",
            )
        )
        request = _close(store, scope, producer)
        with pytest.raises(RecoveryRefused, match="seal_incomplete"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_failed_write_ack_refuses_before_seal(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        # Scratch-only failed acknowledgement models a write without durable success.
        store._write(
            lambda conn: conn.execute(
                "INSERT INTO recovery_write_acks(write_id,session_id,run_id,generation,"
                "mutation,payload_sha256,state,ack_revision,result_json) "
                "VALUES('failed-write',?,'root',0,'message',?,'failed',NULL,NULL)",
                (scope.session_id, "c" * 64),
            )
        )
        with pytest.raises(RecoveryRefused, match="failed_usage_acknowledgement"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_retained_provider_admission_mismatch_refuses(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        altered = evidence.admission.model_copy(update={"source_sha256": "9" * 64})
        raw = altered.canonical_bytes()
        store._write(
            lambda conn: conn.execute(
                "UPDATE recovery_provider_admissions SET source_sha256=?,"
                "admission_json=?,admission_sha256=? WHERE session_id=?",
                ("9" * 64, raw, hashlib.sha256(raw).hexdigest(), scope.session_id),
            )
        )
        with pytest.raises(RecoveryRefused, match="provider_admission_mismatch"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_oversized_source_message_refuses_without_fetch(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        writer = issue_write_permit(producer, store, scope, "root", 0)
        rows = [{"role": "user", "content": "x" * 140_000}]
        assert (
            db.append_messages_batch(
                scope.session_id,
                rows,
                recovery_permit=writer,
                recovery_write_id="oversized-message",
                recovery_payload_sha256=prepare_message_batch(rows).payload_sha256,
            )
            == 1
        )
        request = _close(store, scope, producer)
        selected: list[str] = []
        db._conn.set_trace_callback(selected.append)
        try:
            with pytest.raises(RecoveryRefused, match="source_row_oversized"):
                finalize(store, scope, request, evidence)
        finally:
            db._conn.set_trace_callback(None)
        assert not any('SELECT "id","session_id","role"' in q for q in selected)
        assert store.lookup_root(scope, "root").phase == "closing"
    finally:
        db.close()


def test_committed_seal_rejects_wrong_request_and_scope(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        finalize(store, scope, request, evidence)
        wrong_request = SealRequest(
            request_id=str(uuid4()),
            session_id=scope.session_id,
            run_ids=("root",),
            expected_membership_sha256=membership_sha256(("root",)),
        )
        with pytest.raises(RecoveryRefused, match="close_conflict"):
            finalize(store, scope, wrong_request, None)
        other_scope = RecoveryScope(
            store.store_id, "other-profile", scope.scope_digest, scope.session_id
        )
        with pytest.raises(RecoveryRefused, match="seal_not_found"):
            read_seal_bytes(store, other_scope, "root")
    finally:
        db.close()


def test_expired_deadline_preserves_close_barrier(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        with pytest.raises(RecoveryRefused, match="seal_deadline_exceeded"):
            finalize(store, scope, request, evidence, deadline=time.monotonic() - 1)
        assert store.lookup_root(scope, "root").phase == "closing"
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
    finally:
        db.close()


def test_deadline_after_document_insert_rolls_back_everything(
    tmp_path: Path, monkeypatch
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        original = seal_module._assemble

        def expire_after_assembly(*args, **kwargs):
            assembled = original(*args, **kwargs)
            budget = args[-1]
            budget.active_deadline = time.monotonic() - 1
            return assembled

        monkeypatch.setattr(seal_module, "_assemble", expire_after_assembly)
        with pytest.raises(RecoveryRefused, match="seal_deadline_exceeded"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_sealed_pages WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
    finally:
        db.close()


def test_immutable_page_rejects_update_even_for_store_writer(
    tmp_path: Path, monkeypatch
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        finalize(store, scope, request, evidence)
        with pytest.raises(sqlite3.IntegrityError):
            store._write(
                lambda conn: conn.execute(
                    "UPDATE recovery_sealed_pages SET page_bytes=x'7b7d' "
                    "WHERE session_id=? AND route_page=0",
                    (scope.session_id,),
                )
            )
        assert read_sealed_page_bytes(store, scope, "root", 0)
    finally:
        db.close()


def test_damaged_committed_page_is_refused_on_read(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        finalize(store, scope, request, evidence)
        # A deliberately damaged scratch database models out-of-band file corruption.
        store._write(
            lambda conn: (
                conn.execute(
                    "DROP TRIGGER recovery_guard_recovery_sealed_pages_update"
                ),
                conn.execute(
                    "UPDATE recovery_sealed_pages SET page_bytes=x'7b7d' "
                    "WHERE session_id=? AND route_page=0",
                    (scope.session_id,),
                ),
            )
        )
        with pytest.raises(RecoveryRefused, match="sealed_page_invalid"):
            read_sealed_page_bytes(store, scope, "root", 0)
    finally:
        db.close()


def test_source_walk_queries_use_scope_indexes(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        queries = (
            (
                "SELECT id FROM messages WHERE session_id=? AND id>? ORDER BY id LIMIT 1",
                (scope.session_id, 0),
                "idx_messages_session_id",
            ),
            (
                "SELECT ack_revision,substr(write_id,1,256) FROM recovery_write_acks "
                "WHERE session_id=? AND (ack_revision,write_id)>(?,?) "
                "ORDER BY ack_revision,write_id LIMIT 1",
                (scope.session_id, 0, ""),
                "idx_recovery_write_acks_session_revision",
            ),
            (
                "SELECT sequence FROM recovery_sends WHERE run_id=? AND sequence>? "
                "ORDER BY sequence LIMIT 1",
                ("root", 0),
                "sqlite_autoindex_recovery_sends_",
            ),
            (
                "SELECT model FROM session_model_usage WHERE session_id=? "
                "ORDER BY model,billing_provider,billing_base_url,billing_mode,task LIMIT 1",
                (scope.session_id,),
                "sqlite_autoindex_session_model_usage_",
            ),
            (
                "SELECT sequence FROM recovery_provider_invocations WHERE session_id=? "
                "AND sequence=?",
                (scope.session_id, 0),
                "sqlite_autoindex_recovery_provider_invocations_",
            ),
        )
        for sql, params, index in queries:
            details = " ".join(
                row[3] for row in db._conn.execute("EXPLAIN QUERY PLAN " + sql, params)
            )
            assert "SEARCH" in details and index in details, details
    finally:
        db.close()


def test_aggregate_budget_refuses_before_fetching_next_source_payload(
    tmp_path: Path,
    monkeypatch,
):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        budget = seal_module._Budget(None)
        budget.start()
        budget.charge_value("accounting", {"already": "charged"})
        monkeypatch.setattr(
            seal_module, "MAX_ACCOUNTING_BYTES", budget.accounting_bytes + 1
        )
        selected: list[str] = []
        db._conn.set_trace_callback(selected.append)
        try:
            with pytest.raises(RecoveryRefused, match="snapshot_oversized"):
                seal_module._bounded_row(
                    db._conn,
                    "sessions",
                    SESSION_COLUMNS,
                    "id=?",
                    (scope.session_id,),
                    budget,
                    "accounting",
                )
        finally:
            db._conn.set_trace_callback(None)
        assert any('typeof("id")' in query for query in selected)
        assert not any('SELECT "id","source"' in query for query in selected)
    finally:
        db.close()


def test_snapshot_oversize_preserves_close_barrier(tmp_path: Path, monkeypatch):
    db, store, scope, producer, evidence = _case(tmp_path, monkeypatch)
    try:
        request = _close(store, scope, producer)
        monkeypatch.setattr(seal_module, "MAX_SNAPSHOT_BYTES", 1)
        with pytest.raises(RecoveryRefused, match="snapshot_oversized"):
            finalize(store, scope, request, evidence)
        assert store.lookup_root(scope, "root").phase == "closing"
        assert (
            db._read_one(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            )
            is None
        )
    finally:
        db.close()
