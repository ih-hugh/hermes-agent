"""Abrupt process exits at committed protected-admission and send boundaries.

The writer dies with ``os._exit`` after signaling that its SQLite transaction
committed. A separate spawned reader opens the file after the exit, so this
matrix cannot mistake the writer's in-memory permits for durable authority.
Later recovery tasks extend this file for usage acknowledgement and sealing.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from uuid import UUID

import pytest

from agent.recovery_context import current_incarnation, issue_producer_permit
from agent.recovery_producers import ProducerRegistry
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore, membership_sha256,
)


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
    return AdmissionIdentity(_scope(store), _KEY, _FINGERPRINT, _RUN, current_incarnation())


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

    registry = ProducerRegistry(
        store, scope, _RUN, 0, issue_producer_permit(store, admitted.handoff),
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
