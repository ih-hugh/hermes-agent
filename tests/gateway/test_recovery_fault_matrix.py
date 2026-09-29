"""Abrupt process exits at committed protected-admission and send boundaries.

The writer dies with ``os._exit`` after signaling that its SQLite transaction
committed. A separate spawned reader opens the file after the exit, so this
matrix cannot mistake the writer's in-memory permits for durable authority.
Later recovery tasks extend this file for usage acknowledgement and sealing.
"""

from __future__ import annotations

from tests.recovery_provider_fixture import provider_admission

import os
import sqlite3
import time
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest

from agent.recovery_context import (
    current_incarnation, issue_producer_permit, issue_usage_write_permit,
    issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry, SendOutcome
from gateway.platforms.api_server_recovery_contract import (
    RecoveryAdmission, SealRequest, SealResult,
)
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore, membership_sha256,
)
from hermes_state_recovery_message_result import prepare_message_batch
from hermes_state_recovery_seal import (
    finalize, read_seal_bytes, read_sealed_page_bytes,
)
from hermes_state_usage import UsageDelta
from tests.hermes_state.test_recovery_seal import _case, _close, _close_root, _close_nudge, _nudge


_SESSION = "fault-matrix-session"
_RUN = "run_fault_root"
_KEY = "byf-recovery-v1:fault-root"
_FINGERPRINT = "a" * 64
_SCOPE_DIGEST = "b" * 64
_ATTEMPT = "fault-send-one"
_CLOSE_ID = str(UUID("a2cd4093-3d8b-431e-917a-eef503024682"))
_CRASH_EXIT = 37


def _scope(store: RecoveryStore) -> RecoveryScope:
    return RecoveryScope(store.store_id, "factory", _SCOPE_DIGEST, _SESSION)


def _identity(store: RecoveryStore) -> AdmissionIdentity:
    return AdmissionIdentity(_scope(store), _KEY, _FINGERPRINT, _RUN, current_incarnation(), provider_admission(_SESSION))


def _close_request() -> SealRequest:
    return SealRequest(
        request_id=_CLOSE_ID, session_id=_SESSION, run_ids=[_RUN],
        expected_membership_sha256=membership_sha256([_RUN]),
    )


def _checkpoint_and_exit(signal, milestone: str) -> None:
    signal.send(milestone)
    signal.close()
    os._exit(_CRASH_EXIT)


def _crash_writer(db_path: str, stage: str, signal) -> None:
    db = SessionDB(Path(db_path))
    store = RecoveryStore(db)
    scope = _scope(store)
    if stage == "admission_before_commit":
        _crash_inside_next_write(db, signal, stage)
    admitted = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        _identity(store),
    )
    assert admitted.outcome == "created" and admitted.handoff is not None
    if stage == "admission":
        _checkpoint_and_exit(signal, stage)
    if stage == "closing":
        view = store.begin_close(scope, _close_request())
        assert view.phase == "closing" and view.request_id == _CLOSE_ID
        _checkpoint_and_exit(signal, stage)
    if stage == "closing_before_commit":
        _crash_inside_next_write(db, signal, stage)
        store.begin_close(scope, _close_request())

    registry = ProducerRegistry(
        store, scope, _RUN, 0, issue_producer_permit(store, admitted.handoff),
    )
    if stage == "producer_registration_before_commit":
        _crash_inside_next_write(db, signal, stage)
        store.register_producer(
            scope, _RUN, registry.permit, "precommit-producer", "executor",
        )
    if stage == "producer_running":
        registry.enter(registry.permit, "executor").run(
            lambda: _checkpoint_and_exit(signal, stage))
    if stage in {"send_reserved", "send_invoking"}:
        def sdk_body() -> None:
            send = registry.sends.begin(registry.permit, _ATTEMPT)
            if stage == "send_reserved":
                _checkpoint_and_exit(signal, stage)
            send.invoke(lambda: _checkpoint_and_exit(signal, stage))

        registry.enter(registry.permit, "sdk").run(sdk_body)
    raise AssertionError("writer did not exit at its requested milestone")


def _spawn_abrupt_writer(db_path: Path, stage: str) -> None:
    context = get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_crash_writer, args=(str(db_path), stage, writer))
    try:
        process.start()
        writer.close()
        assert reader.poll(15), f"writer did not commit {stage}"
        assert reader.recv() == stage
        process.join(timeout=15)
        assert process.exitcode == _CRASH_EXIT
    finally:
        reader.close()
        writer.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)


def _fresh_process_snapshot(db_path: str) -> dict:
    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        scope = _scope(store)
        keyed = store.lookup_key(scope, _KEY, _FINGERPRINT)
        session = db._read_one(
            "SELECT phase,revision,close_request_id,receipt_json FROM recovery_sessions WHERE session_id=?",
            (_SESSION,),
        )
        member = db._read_one(
            "SELECT owner_incarnation,producer_state,idempotency_key,request_sha256 "
            "FROM recovery_members WHERE run_id=?", (_RUN,),
        )
        producers = db._read_all(
            "SELECT kind,state,owner_incarnation FROM recovery_producers WHERE run_id=? ORDER BY kind",
            (_RUN,),
        )
        usage = db._read_all(
            "SELECT delta_id,attempt_id,state,payload_sha256,ack_revision "
            "FROM recovery_usage_slots ORDER BY delta_id",
        )
        try:
            close_view = store.lookup_root(scope, _RUN)
        except RecoveryRefused as exc:
            assert exc.code == "not_found"
            close_view = None
        assert keyed is not None and keyed.member is not None
        return {
            "store_id": store.store_id,
            "key_outcome": keyed.outcome,
            "key_handoff": keyed.handoff is not None,
            "key_member": keyed.member.model_dump(),
            "session": tuple(session),
            "member": tuple(member),
            "producers": [tuple(row) for row in producers],
            "sends": store.send_inventory(scope, _RUN),
            "usage": [tuple(row) for row in usage],
            "close": None if close_view is None else (
                close_view.phase, close_view.revision, close_view.request_id,
                tuple(member.run_id for member in close_view.members), close_view.receipt_ref,
            ),
        }
    finally:
        db.close()


def _snapshot_after_restart(db_path: Path) -> dict:
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        return pool.submit(_fresh_process_snapshot, str(db_path)).result(timeout=20)


def _fresh_unadmitted_snapshot(db_path: str) -> dict:
    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        scope = _scope(store)
        return {
            "store_id": store.store_id,
            "key": store.lookup_key(scope, _KEY, _FINGERPRINT),
            "source": db._read_one("SELECT 1 FROM sessions WHERE id=?", (_SESSION,)),
            "sessions": db._read_one("SELECT COUNT(*) FROM recovery_sessions")[0],
            "members": db._read_one("SELECT COUNT(*) FROM recovery_members")[0],
            "producers": db._read_one("SELECT COUNT(*) FROM recovery_producers")[0],
            "guards": tuple(row[0] for row in db._read_all(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'recovery_guard_*' ORDER BY name"
            )),
        }
    finally:
        db.close()


def _unadmitted_snapshot_after_restart(db_path: Path) -> dict:
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        return pool.submit(_fresh_unadmitted_snapshot, str(db_path)).result(timeout=20)


def _assert_no_recreated_authority(db_path: Path, before: dict) -> None:
    db = SessionDB(db_path)
    try:
        store = RecoveryStore(db)
        scope = _scope(store)
        replay = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
            _identity(store),
        )
        assert replay.outcome == "replayed"
        assert replay.member is not None and replay.member.run_id == _RUN
        assert replay.handoff is None
        with pytest.raises(RecoveryRefused):
            issue_producer_permit(store, replay.handoff)
        with pytest.raises(RecoveryRefused):
            store.close_producer(scope, _RUN, None)
        if before["close"] is None:
            close = store.begin_close(scope, _close_request())
            assert close.phase == "closing" and close.request_id == _CLOSE_ID
        else:
            close = store.begin_close(scope, _close_request())
            assert close.revision == before["close"][1]
        assert close.members[0].run_id == _RUN
        assert close.members[0].producer_state == "open"
        assert close.receipt_ref is None and close.state != "sealed"
    finally:
        db.close()


def _expire_ordinary_transport(tmp_path: Path) -> None:
    """Advance only the legacy transport record; protected rows have no TTL."""
    legacy = RunIdempotencyStore(str(tmp_path / "runs_idempotency.db"))
    try:
        assert legacy.reserve(
            _SCOPE_DIGEST, "ordinary-key", "f" * 64, "run_ordinary",
            {"status": "completed"},
        )[0] == "created"
        legacy._conn.execute(
            "UPDATE run_idempotency SET updated_at=? WHERE run_id=?",
            (time.time() - legacy.RETENTION_SECONDS - 1, "run_ordinary"),
        )
        legacy._conn.commit()
        assert legacy.lookup(_SCOPE_DIGEST, "ordinary-key", "f" * 64)[0] == "missing"
    finally:
        legacy.close()


@pytest.mark.parametrize("stage", [
    "admission", "producer_running", "send_reserved", "send_invoking", "closing",
])
def test_abrupt_exit_keeps_exact_durable_evidence_and_no_authority(tmp_path: Path, stage: str):
    db_path = tmp_path / "state.db"
    _spawn_abrupt_writer(db_path, stage)
    before = _snapshot_after_restart(db_path)
    assert before["key_outcome"] == "replayed" and not before["key_handoff"]
    assert before["key_member"] == {
        "run_id": _RUN, "generation": 0, "parent_run_id": None,
        "request_sha256": _FINGERPRINT, "producer_state": "open",
    }
    assert before["member"][1:] == ("open", _KEY, _FINGERPRINT)
    assert before["member"][0] != current_incarnation()
    assert before["session"][0] == ("closing" if stage == "closing" else "open")
    assert before["session"][3] is None  # no receipt/no-call claim from PID disappearance
    if stage == "closing":
        assert before["close"] is not None and before["close"][2] == _CLOSE_ID
    else:
        assert before["close"] is None
    if stage in {"admission", "closing"}:
        assert before["producers"] == [] and before["sends"] == () and before["usage"] == []
    else:
        assert len(before["producers"]) == 1
        assert before["producers"][0][:2] == (
            "executor" if stage == "producer_running" else "sdk", "running",
        )
        assert before["producers"][0][2] == before["member"][0]
        if stage == "producer_running":
            assert before["sends"] == () and before["usage"] == []
        else:
            assert before["sends"] == ((_ATTEMPT, 1, "invoking" if stage == "send_invoking" else "reserved",
                                        f"{_ATTEMPT}:usage"),)
            assert before["usage"] == [(
                f"{_ATTEMPT}:usage", _ATTEMPT, "pending", None, None,
            )]
    if stage == "send_reserved":
        _expire_ordinary_transport(tmp_path)
        assert _snapshot_after_restart(db_path) == before
    _assert_no_recreated_authority(db_path, before)
    after = _snapshot_after_restart(db_path)
    assert after["store_id"] == before["store_id"]
    assert after["key_member"] == before["key_member"]
    assert after["member"] == before["member"]
    assert after["producers"] == before["producers"]
    assert after["sends"] == before["sends"]
    assert after["usage"] == before["usage"]
    assert after["close"] is not None and after["close"][0] == "closing"
    assert after["close"][2:] == (_CLOSE_ID, (_RUN,), None)
    assert after["session"][3] is None


def _crash_inside_next_write(db: SessionDB, signal, stage: str, *, call: int = 1) -> None:
    """Exit after the real callback mutates SQLite, before its real COMMIT."""
    original = db._execute_write
    number = 0

    def _write(fn, patience_s=None):
        nonlocal number
        number += 1
        selected = number == call

        def _callback(conn):
            result = fn(conn)
            if selected:
                _checkpoint_and_exit(signal, stage)
            return result

        return original(_callback, patience_s=patience_s)

    db._execute_write = _write


@pytest.mark.parametrize("stage", [
    "admission_before_commit", "producer_registration_before_commit",
    "closing_before_commit",
])
def test_abrupt_exit_before_admission_producer_and_close_commits(
    tmp_path: Path, stage: str,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_abrupt_writer(db_path, stage)
    if stage == "admission_before_commit":
        snapshot = _unadmitted_snapshot_after_restart(db_path)
        assert snapshot["store_id"]
        assert snapshot["key"] is None and snapshot["source"] is None
        assert snapshot["sessions"] == snapshot["members"] == snapshot["producers"] == 0
        assert snapshot["guards"] == tuple(sorted((
            "recovery_guard_recovery_exclusions_insert",
            "recovery_guard_recovery_exclusions_update",
            "recovery_guard_recovery_exclusions_delete",
        )))
        assert _unadmitted_snapshot_after_restart(db_path) == snapshot
    else:
        snapshot = _snapshot_after_restart(db_path)
        assert snapshot["key_outcome"] == "replayed"
        assert snapshot["key_handoff"] is False
        assert snapshot["member"][1] == "open"
        assert snapshot["producers"] == []
        assert snapshot["sends"] == () and snapshot["usage"] == []
        assert snapshot["session"][0] == "open"
        assert snapshot["session"][2:] == (None, None)
        assert snapshot["close"] is None
        assert _snapshot_after_restart(db_path) == snapshot


def _usage_delta(send, *, actual_cost: float | None = None) -> UsageDelta:
    return UsageDelta(
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
        actual_cost_usd=actual_cost,
        cost_status="known" if actual_cost is not None else "estimated",
        cost_source="scratch-price-table",
        pricing_version="2026-09",
    )


def _started_send(store: RecoveryStore, scope: RecoveryScope, producer):
    registry = ProducerRegistry(store, scope, "root", 0, producer)

    def _invoke():
        send = registry.sends.begin(registry.permit, "fault-accounted-send")
        send.invoke(lambda: None)
        return send

    return registry.enter(registry.permit, "sdk").run(_invoke)


def _finalization_fault_writer(db_path: str, stage: str, signal) -> None:
    # pytest.MonkeyPatch only binds a synthetic selected provider in this child.
    # No terminal, gateway, model SDK, or external resource is invoked.
    with pytest.MonkeyPatch.context() as monkeypatch:
        db, store, scope, producer, evidence = _case(Path(db_path).parent, monkeypatch)
        if stage.startswith("transcript_"):
            writer = issue_write_permit(producer, store, scope, "root", 0)
            rows = [{"role": "user", "content": "durable transcript"}]
            if stage == "transcript_before_commit":
                # guarded_write first commits a pending ack, then atomically
                # appends the message and commits the acknowledgement.
                _crash_inside_next_write(db, signal, stage, call=2)
            db.append_messages_batch(
                scope.session_id, rows,
                recovery_permit=writer,
                recovery_write_id="fault-transcript-ack",
                recovery_payload_sha256=prepare_message_batch(rows).payload_sha256,
            )
            _checkpoint_and_exit(signal, stage)

        if stage.startswith(("usage_", "send_", "cost_")):
            send = _started_send(store, scope, producer)
            usage_writer = issue_usage_write_permit(store, send.completion)
            delta = _usage_delta(send, actual_cost=0.0 if stage == "cost_known_zero" else None)
            store.reserve_usage_payload(usage_writer, delta, delta.digest())
            if stage == "usage_before_commit":
                _crash_inside_next_write(db, signal, stage)
            store.apply_usage_delta(usage_writer, delta, delta.digest())
            if stage == "usage_after_commit":
                _checkpoint_and_exit(signal, stage)
            if stage == "send_before_commit":
                _crash_inside_next_write(db, signal, stage)
            send.finish(SendOutcome(
                kind="accounted", attempt_id=send.attempt_id,
                acknowledged_delta_ids=(send.delta_id,),
            ))
            if stage == "send_after_commit":
                _checkpoint_and_exit(signal, stage)
            if stage.startswith("cost_"):
                request = _close(store, scope, producer)
                assert finalize(store, scope, request, evidence).state == "sealed"
                _checkpoint_and_exit(signal, stage)

        if stage in {
            "seal_before_commit", "seal_after_commit", "seal_root_nudge",
            "seal_queued_stop", "seal_with_transcript",
        }:
            if stage == "seal_root_nudge":
                _close_root(store, scope, producer)
                nudge = _nudge(store, scope, evidence.admission)
                _close_nudge(store, scope, nudge)
                request = SealRequest(
                    request_id=_CLOSE_ID,
                    session_id=scope.session_id,
                    run_ids=("root", "nudge"),
                    expected_membership_sha256=membership_sha256(("root", "nudge")),
                )
                assert store.begin_close(scope, request).phase == "closing"
            elif stage == "seal_queued_stop":
                minimal = db._read_one(
                    "SELECT source,profile_name,started_at,model,api_call_count "
                    "FROM sessions WHERE id=?", (scope.session_id,),
                )
                assert minimal[:2] == ("api_server", "factory")
                assert type(minimal[2]) is float and minimal[2] > 0
                assert minimal[3:] == (None, 0)
                # The admitted root is cancelled before any executor or SDK
                # producer starts. Only its status callback records the stop.
                store.register_producer(scope, "root", producer, "stop-barrier", "callback")
                store.start_registered_producer(scope, "root", producer, "stop-barrier")
                store.update_status("root", {"status": "cancelled"})
                store.close_registered_producer(scope, "root", producer, "stop-barrier")
                store.close_producer(scope, "root", producer)
                request = SealRequest(
                    request_id=_CLOSE_ID, session_id=scope.session_id,
                    run_ids=("root",),
                    expected_membership_sha256=membership_sha256(("root",)),
                )
                assert store.begin_close(scope, request).phase == "closing"
            else:
                if stage == "seal_with_transcript":
                    writer = issue_write_permit(producer, store, scope, "root", 0)
                    rows = [{"role": "user", "content": "retained after transport prune"}]
                    db.append_messages_batch(
                        scope.session_id, rows,
                        recovery_permit=writer,
                        recovery_write_id="retained-transcript-ack",
                        recovery_payload_sha256=prepare_message_batch(rows).payload_sha256,
                    )
                request = _close(store, scope, producer)
            if stage == "seal_before_commit":
                _crash_inside_next_write(db, signal, stage)
            assert finalize(store, scope, request, evidence).state == "sealed"
            _checkpoint_and_exit(signal, stage)

        if stage in {"pending_producer", "unknown_send"}:
            if stage == "pending_producer":
                store.register_producer(scope, "root", producer, "pending-callback", "callback")
                store.start_registered_producer(scope, "root", producer, "pending-callback")
            else:
                send = _started_send(store, scope, producer)
                send.finish(SendOutcome(
                    kind="unknown", attempt_id=send.attempt_id, reason="scratch-unknown",
                ))
            request = SealRequest(
                request_id=_CLOSE_ID, session_id=scope.session_id,
                run_ids=("root",), expected_membership_sha256=membership_sha256(("root",)),
            )
            assert store.begin_close(scope, request).phase == "closing"
            with pytest.raises(RecoveryRefused):
                finalize(store, scope, request, evidence)
            _checkpoint_and_exit(signal, stage)

    raise AssertionError("writer did not exit at its requested milestone")


def _spawn_finalization_fault(db_path: Path, stage: str) -> None:
    context = get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(
        target=_finalization_fault_writer, args=(str(db_path), stage, writer)
    )
    try:
        process.start()
        writer.close()
        assert reader.poll(20), f"writer did not reach {stage}"
        assert reader.recv() == stage
        process.join(timeout=20)
        assert process.exitcode == _CRASH_EXIT
    finally:
        reader.close()
        writer.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)


def _fresh_finalization_snapshot(db_path: str) -> dict:
    from pydantic import TypeAdapter
    from gateway.platforms.api_server_recovery_contract import (
        SealedArtifactPage, verify_sealed_pages,
    )
    from hermes_state_recovery_values import SemanticContext, verify_artifact_crosslinks

    db = SessionDB(Path(db_path))
    try:
        store = RecoveryStore(db)
        scope = RecoveryScope(store.store_id, "factory", _SCOPE_DIGEST, "seal-session")
        session = tuple(db._read_one(
            "SELECT phase,revision,close_request_json,receipt_json "
            "FROM recovery_sessions WHERE session_id=?", (scope.session_id,),
        ))
        source = tuple(db._read_one(
            "SELECT source,profile_name,started_at,model,api_call_count,input_tokens,"
            "output_tokens,estimated_cost_usd,actual_cost_usd,cost_status "
            "FROM sessions WHERE id=?", (scope.session_id,),
        ))
        messages = [tuple(row) for row in db._read_all(
            "SELECT role,content FROM messages WHERE session_id=? ORDER BY id",
            (scope.session_id,),
        )]
        acks = [tuple(row) for row in db._read_all(
            "SELECT write_id,state,payload_sha256,ack_revision FROM recovery_write_acks "
            "WHERE session_id=? ORDER BY write_id", (scope.session_id,),
        )]
        usage = [tuple(row) for row in db._read_all(
            "SELECT delta_id,state,payload_sha256,ack_revision FROM recovery_usage_slots "
            "ORDER BY delta_id"
        )]
        models = [tuple(row) for row in db._read_all(
            "SELECT model,billing_provider,api_call_count,input_tokens,output_tokens,"
            "estimated_cost_usd,actual_cost_usd FROM session_model_usage "
            "WHERE session_id=?", (scope.session_id,),
        )]
        sends = store.send_inventory(scope, "root")
        members = [tuple(row) for row in db._read_all(
            "SELECT run_id,generation,producer_state,status_json,owner_incarnation "
            "FROM recovery_members "
            "WHERE session_id=? ORDER BY generation", (scope.session_id,),
        )]
        documents = db._read_one(
            "SELECT COUNT(*) FROM recovery_seal_documents WHERE session_id=?",
            (scope.session_id,),
        )[0]
        pages = db._read_one(
            "SELECT COUNT(*) FROM recovery_sealed_pages WHERE session_id=?",
            (scope.session_id,),
        )[0]
        result_bytes = None
        page_bytes = ()
        semantic = None
        if documents:
            result_bytes = read_seal_bytes(store, scope, "root")
            result = SealResult.model_validate_json(result_bytes)
            assert result.receipt is not None
            page_bytes = tuple(
                read_sealed_page_bytes(store, scope, "root", index)
                for index in range(pages)
            )
            adapter = TypeAdapter(SealedArtifactPage)
            parsed_pages = [adapter.validate_json(page) for page in page_bytes]
            verify_sealed_pages(result.receipt, parsed_pages)
            sections = {kind: [] for kind in (
                "transcript", "accounting", "send_ledger", "provider_invocations",
            )}
            for page in parsed_pages:
                if page.kind == "data":
                    sections[page.body.kind].extend(
                        row.model_dump(mode="json")["value"] for row in page.body.rows
                    )
            checked = verify_artifact_crosslinks(
                sections,
                SemanticContext(
                    session_id=scope.session_id,
                    members=tuple((m.run_id, m.generation) for m in result.receipt.members),
                    provider_container_id=result.receipt.provider_binding.container_id,
                    provider_attestation_sha256=(
                        result.receipt.provider_binding.container_attestation_sha256
                    ),
                    no_calls=result.receipt.no_calls,
                ),
            )
            assert checked.route_replay_complete
            request = SealRequest.model_validate_json(session[2])
            assert finalize(store, scope, request, None) == result
            semantic = {
                "members": tuple((m.run_id, m.generation) for m in result.receipt.members),
                "no_calls": result.receipt.no_calls,
                "usage": checked.acknowledged_usage.model_dump(mode="json"),
            }
        return {
            "store_id": store.store_id, "session": session, "source": source,
            "messages": messages, "acks": acks, "usage": usage, "models": models,
            "sends": sends, "members": members,
            "documents": documents, "pages": pages,
            "result_bytes": result_bytes, "page_bytes": page_bytes,
            "semantic": semantic,
        }
    finally:
        db.close()


def _finalization_snapshot_after_restart(db_path: Path) -> dict:
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        return pool.submit(_fresh_finalization_snapshot, str(db_path)).result(timeout=20)


@pytest.mark.parametrize("stage", [
    "transcript_before_commit", "transcript_after_commit",
    "usage_before_commit", "usage_after_commit",
    "send_before_commit", "send_after_commit",
])
def test_crash_at_actual_transcript_and_accounting_transactions(
    tmp_path: Path, stage: str,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, stage)
    first = _finalization_snapshot_after_restart(db_path)
    assert first["session"][0] == "open"
    assert first["documents"] == first["pages"] == 0
    assert first["result_bytes"] is None
    assert first["source"][:2] == ("api_server", "factory")
    assert first["members"][0][2] == "open"
    assert first["members"][0][4] != current_incarnation()
    if stage.startswith("transcript_"):
        assert len(first["acks"]) == 1
        assert first["acks"][0][0] == "fault-transcript-ack"
        if stage == "transcript_before_commit":
            assert first["acks"][0][1] == "pending"
            assert first["messages"] == []
        else:
            assert first["acks"][0][1] == "committed"
            assert first["acks"][0][3] > 0
            assert first["messages"] == [("user", "durable transcript")]
        assert first["usage"] == [] and first["sends"] == ()
    else:
        assert first["acks"] == [] and first["messages"] == []
        assert len(first["usage"]) == len(first["sends"]) == 1
        assert first["usage"][0][2] is not None  # retained exact payload
        applied = stage != "usage_before_commit"
        assert first["usage"][0][1] == ("committed" if applied else "pending")
        assert first["source"][4:7] == ((1, 17, 4) if applied else (0, 0, 0))
        assert len(first["models"]) == int(applied)
        if applied:
            assert first["models"][0][2:5] == (1, 17, 4)
        assert first["sends"][0][2] == (
            "accounted" if stage == "send_after_commit" else "invoking"
        )
    # A second process has no write/producer permit yet observes the identical
    # committed evidence. A dead owner does not close the root on its behalf.
    assert _finalization_snapshot_after_restart(db_path) == first


@pytest.mark.parametrize("stage", ["seal_before_commit", "seal_after_commit"])
def test_crash_brackets_actual_seal_document_pages_and_tombstone(
    tmp_path: Path, stage: str,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, stage)
    first = _finalization_snapshot_after_restart(db_path)
    assert first["messages"] == first["acks"] == first["usage"] == []
    assert first["source"][:2] == ("api_server", "factory")
    if stage == "seal_before_commit":
        assert first["session"][0] == "closing"
        assert first["session"][3] is None
        assert first["documents"] == first["pages"] == 0
        assert first["result_bytes"] is None and first["page_bytes"] == ()
    else:
        assert first["session"][0] == "sealed"
        assert first["session"][3] is not None
        assert first["documents"] == 1 and first["pages"] >= 1
        assert first["semantic"]["members"] == (("root", 0),)
        assert first["semantic"]["no_calls"] is True
        assert first["semantic"]["usage"]["api_call_count"] == 0
    assert _finalization_snapshot_after_restart(db_path) == first


def test_root_and_nudge_sealed_membership_and_minimal_no_call_row_survive_restart(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, "seal_root_nudge")
    first = _finalization_snapshot_after_restart(db_path)
    assert first["session"][0] == "sealed"
    assert first["semantic"]["members"] == (("root", 0), ("nudge", 1))
    assert first["semantic"]["no_calls"] is True
    assert first["source"][0] == "api_server"
    assert first["source"][1] == "factory"
    assert type(first["source"][2]) is float and first["source"][2] > 0
    assert first["source"][3:7] == (None, 0, 0, 0)
    assert first["messages"] == first["acks"] == first["usage"] == []
    assert _finalization_snapshot_after_restart(db_path) == first


def test_queued_stopped_root_seals_from_admitted_minimal_source_row(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, "seal_queued_stop")
    first = _finalization_snapshot_after_restart(db_path)
    assert first["session"][0] == "sealed"
    assert first["semantic"]["members"] == (("root", 0),)
    assert first["semantic"]["no_calls"] is True
    assert first["source"][3:7] == (None, 0, 0, 0)
    assert [member[:4] for member in first["members"]] == [
        ("root", 0, "closed", '{"status":"cancelled"}')
    ]
    assert first["messages"] == first["acks"] == first["usage"] == []
    assert _finalization_snapshot_after_restart(db_path) == first


@pytest.mark.parametrize("stage, expected_cost", [
    ("cost_known_zero", 0.0), ("cost_unobserved", None),
])
def test_known_zero_and_unobserved_cost_remain_distinct_in_sealed_replay(
    tmp_path: Path, stage: str, expected_cost: float | None,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, stage)
    first = _finalization_snapshot_after_restart(db_path)
    assert first["session"][0] == "sealed"
    assert first["semantic"]["no_calls"] is False
    assert first["semantic"]["usage"]["api_call_count"] == 1
    assert first["semantic"]["usage"]["input_tokens"] == 17
    assert first["semantic"]["usage"]["actual_cost_usd"] == expected_cost
    assert first["semantic"]["usage"]["cost_status"] == (
        "known" if expected_cost is not None else "estimated"
    )
    assert first["sends"][0][2] == "accounted"
    assert _finalization_snapshot_after_restart(db_path) == first


@pytest.mark.parametrize("stage", ["pending_producer", "unknown_send"])
def test_dead_owner_pending_or_unknown_work_never_mints_a_seal(
    tmp_path: Path, stage: str,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, stage)
    first = _finalization_snapshot_after_restart(db_path)
    assert first["session"][0] == "closing"
    assert first["session"][3] is None
    assert first["documents"] == first["pages"] == 0
    assert first["result_bytes"] is None
    if stage == "unknown_send":
        assert first["sends"][0][2] == "unknown"
    assert _finalization_snapshot_after_restart(db_path) == first


def test_ordinary_24_hour_retention_prune_preserves_sealed_evidence(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    _spawn_finalization_fault(db_path, "seal_with_transcript")
    before = _finalization_snapshot_after_restart(db_path)
    assert before["messages"] == [("user", "retained after transport prune")]
    assert len(before["acks"]) == 1 and before["acks"][0][1] == "committed"
    now = time.time()
    legacy = RunIdempotencyStore(str(tmp_path / "runs_idempotency.db"))
    try:
        with patch("gateway.platforms.api_server_run_idempotency.time.time", return_value=now):
            assert legacy.reserve(
                _SCOPE_DIGEST, "ordinary-terminal", "f" * 64,
                "run_ordinary", {"status": "completed"},
            )[0] == "created"
        with patch(
            "gateway.platforms.api_server_run_idempotency.time.time",
            return_value=now + legacy.RETENTION_SECONDS + 1,
        ):
            assert legacy.lookup(_SCOPE_DIGEST, "ordinary-terminal", "f" * 64)[0] == "missing"
    finally:
        legacy.close()
    after = _finalization_snapshot_after_restart(db_path)
    assert after == before
    assert after["session"][0] == "sealed"
    assert after["result_bytes"] and after["page_bytes"]
