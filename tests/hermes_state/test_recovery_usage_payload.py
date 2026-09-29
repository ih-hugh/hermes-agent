"""Exact protected usage deltas remain auditable after the writer and process exit."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agent.recovery_context import (
    bind_write_permit,
    current_incarnation,
    issue_producer_permit,
    issue_usage_write_permit,
    issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry, SendOutcome
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
    membership_sha256,
)
from hermes_state_usage import UsageDelta


def _pending_send(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation()),
    )
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff)
    )
    generic_writer = issue_write_permit(registry.permit, store, scope, "root", 0)
    with bind_write_permit(generic_writer):
        db.create_session(scope.session_id, "api_server")

    def _invoke():
        send = registry.sends.begin(registry.permit, "attempt-payload")
        send.invoke(lambda: None)
        return send

    send = registry.enter(registry.permit, "sdk").run(_invoke)
    usage_writer = issue_usage_write_permit(store, send.completion)
    return db, store, scope, registry, send, usage_writer


def _delta(send, **overrides) -> UsageDelta:
    base = UsageDelta(
        write_id=send.delta_id,
        attempt_id=send.attempt_id,
        generation=0,
        model="model-😀",
        billing_provider="provider-x",
        billing_base_url="https://provider.example/route",
        billing_mode="subscription_included",
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
    return replace(base, **overrides)


def _read_all(store: RecoveryStore, scope: RecoveryScope):
    return store._write(lambda conn: tuple(store.iter_committed_usage_payloads(scope, conn=conn)))


def _another_send(registry: ProducerRegistry, store: RecoveryStore, attempt_id: str):
    def _invoke():
        send = registry.sends.begin(registry.permit, attempt_id)
        send.invoke(lambda: None)
        return send

    send = registry.enter(registry.permit, "sdk").run(_invoke)
    return send, issue_usage_write_permit(store, send.completion)


@pytest.mark.parametrize("stage", ["reserve", "apply", "read"])
def test_mismatched_send_and_slot_delta_refuses_at_every_seam(tmp_path: Path, stage: str) -> None:
    db, store, scope, _, send, permit = _pending_send(tmp_path)
    delta = _delta(send)
    try:
        if stage != "reserve":
            store.reserve_usage_payload(permit, delta, delta.digest())
        if stage == "read":
            store.apply_usage_delta(permit, delta, delta.digest())
        store._write(lambda conn: conn.execute(
            "UPDATE recovery_sends SET delta_id='other-delta' WHERE attempt_id=?",
            (send.attempt_id,),
        ))
        if stage == "reserve":
            with pytest.raises(RecoveryRefused):
                store.reserve_usage_payload(permit, delta, delta.digest())
        elif stage == "apply":
            with pytest.raises(RecoveryRefused):
                store.apply_usage_delta(permit, delta, delta.digest())
            assert db.get_session(scope.session_id)["input_tokens"] == 0
        else:
            with pytest.raises(RecoveryRefused):
                _read_all(store, scope)
    finally:
        db.close()


def test_reservation_refuses_producer_bound_to_different_member(tmp_path: Path) -> None:
    db, store, scope, _, send, permit = _pending_send(tmp_path)
    delta = _delta(send)
    try:
        def _tamper(conn):
            conn.execute(
                "INSERT INTO recovery_members(run_id,session_id,generation,parent_run_id,"
                "profile,scope_digest,idempotency_key,request_sha256,owner_incarnation,"
                "producer_state,status_json) "
                "SELECT 'other-run',session_id,1,run_id,profile,scope_digest,"
                "'byf-recovery-v1:other',request_sha256,owner_incarnation,'open','{}' "
                "FROM recovery_members WHERE run_id='root'"
            )
            conn.execute(
                "UPDATE recovery_producers SET run_id='other-run' WHERE producer_id="
                "(SELECT producer_id FROM recovery_sends WHERE attempt_id=?)",
                (send.attempt_id,),
            )

        store._write(_tamper)
        with pytest.raises(RecoveryRefused, match="invalid_usage_permit"):
            store.reserve_usage_payload(permit, delta, delta.digest())
        assert tuple(db._read_one(
            "SELECT payload_sha256,payload_json FROM recovery_usage_slots WHERE delta_id=?",
            (delta.write_id,),
        )) == (None, None)
    finally:
        db.close()


@pytest.mark.parametrize("overrides,field", [
    ({"input_tokens": 2**63 - 1}, "input_tokens"),
    ({"estimated_cost_usd": 1e308, "actual_cost_usd": 1e308}, "estimated_cost_usd"),
])
def test_cumulative_overflow_rolls_back_both_rows_and_ack(
    tmp_path: Path, overrides: dict, field: str,
) -> None:
    db, store, scope, registry, first_send, first_permit = _pending_send(tmp_path)
    second_send, second_permit = _another_send(registry, store, "attempt-overflow")
    first = _delta(first_send, **overrides)
    second = _delta(
        second_send,
        input_tokens=1 if field == "input_tokens" else 0,
        output_tokens=0, cache_read_tokens=0, cache_write_tokens=0, reasoning_tokens=0,
        estimated_cost_usd=1e308 if field == "estimated_cost_usd" else 0,
        actual_cost_usd=1e308 if field == "estimated_cost_usd" else None,
    )
    try:
        store.reserve_usage_payload(first_permit, first, first.digest())
        store.apply_usage_delta(first_permit, first, first.digest())
        first_send.finish(SendOutcome(
            kind="accounted", attempt_id=first_send.attempt_id,
            acknowledged_delta_ids=(first_send.delta_id,),
        ))
        session_before = db._read_one(
            "SELECT input_tokens,estimated_cost_usd,actual_cost_usd,api_call_count "
            "FROM sessions WHERE id=?", (scope.session_id,),
        )
        model_before = db._read_one(
            "SELECT input_tokens,estimated_cost_usd,actual_cost_usd,api_call_count "
            "FROM session_model_usage WHERE session_id=? AND task=''", (scope.session_id,),
        )
        assert type(session_before[0 if field == "input_tokens" else 1]) is (
            int if field == "input_tokens" else float
        )
        store.reserve_usage_payload(second_permit, second, second.digest())
        with pytest.raises(RecoveryRefused, match="invalid_usage_totals"):
            store.apply_usage_delta(second_permit, second, second.digest())
        assert tuple(db._read_one(
            "SELECT input_tokens,estimated_cost_usd,actual_cost_usd,api_call_count "
            "FROM sessions WHERE id=?", (scope.session_id,),
        )) == tuple(session_before)
        assert tuple(db._read_one(
            "SELECT input_tokens,estimated_cost_usd,actual_cost_usd,api_call_count "
            "FROM session_model_usage WHERE session_id=? AND task=''", (scope.session_id,),
        )) == tuple(model_before)
        assert tuple(db._read_one(
            "SELECT state,ack_revision FROM recovery_usage_slots WHERE delta_id=?",
            (second.write_id,),
        )) == ("pending", None)
        store.fail_usage_delta(second_permit)
        assert tuple(db._read_one(
            "SELECT state,ack_revision FROM recovery_usage_slots WHERE delta_id=?",
            (second.write_id,),
        )) == ("abandoned", None)
    finally:
        db.close()


def test_complete_canonical_delta_survives_closing_reopen_and_new_process(tmp_path: Path) -> None:
    db, store, scope, _, send, permit = _pending_send(tmp_path)
    delta = _delta(send)
    canonical = delta.canonical_bytes()
    try:
        store.begin_close(
            scope,
            SealRequest(
                request_id="123e4567-e89b-42d3-a456-426614174000",
                session_id=scope.session_id,
                run_ids=["root"],
                expected_membership_sha256=membership_sha256(["root"]),
            ),
        )
        assert db.queue_recovery_usage(permit, delta) == delta.write_id
        assert db.wait_recovery_write_ack(scope, delta.write_id, timeout=5).state == "committed"
        assert db.get_session(scope.session_id)["actual_cost_usd"] is None
        send.finish(SendOutcome(
            kind="accounted", attempt_id=send.attempt_id,
            acknowledged_delta_ids=(send.delta_id,),
        ))
        retained = _read_all(store, scope)
        assert len(retained) == 1
        assert retained[0].delta == delta
        assert retained[0].payload_json == canonical
        assert retained[0].payload_sha256 == hashlib.sha256(canonical).hexdigest()
        assert retained[0].producer_id == db._read_one(
            "SELECT producer_id FROM recovery_sends WHERE attempt_id=?", (send.attempt_id,),
        )[0]
        assert retained[0].ack_revision > 0
        assert _read_all(store, scope) == retained
        assert db.queue_recovery_usage(permit, delta) == delta.write_id
        assert db.get_session(scope.session_id)["input_tokens"] == 17
    finally:
        db.close()

    script = (
        "import json,sys; from pathlib import Path; from hermes_state import SessionDB; "
        "from hermes_state_recovery import RecoveryStore,RecoveryScope; "
        "db=SessionDB(Path(sys.argv[1])); store=RecoveryStore(db); "
        "scope=RecoveryScope(store.store_id,'factory','b'*64,'protected-session'); "
        "row=store._write(lambda conn: tuple(store.iter_committed_usage_payloads(scope,conn=conn)))[0]; "
        "print(json.dumps({'hex':row.payload_json.hex(),'digest':row.payload_sha256,"
        "'model':row.delta.model,'actual':row.delta.actual_cost_usd})); db.close()"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "state.db")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout.strip().splitlines()[-1])
    assert observed == {
        "hex": canonical.hex(),
        "digest": delta.digest(),
        "model": "model-😀",
        "actual": None,
    }


def test_first_reservation_rejects_changed_retry_and_mutated_original(tmp_path: Path) -> None:
    db, store, scope, _, send, permit = _pending_send(tmp_path)
    delta = _delta(send)
    canonical = delta.canonical_bytes()
    try:
        assert store.reserve_usage_payload(permit, delta, delta.digest()) == "pending"
        raw = db._read_one(
            "SELECT payload_json,payload_sha256 FROM recovery_usage_slots WHERE delta_id=?",
            (delta.write_id,),
        )
        assert tuple(raw) == (canonical, delta.digest())
        with pytest.raises(RecoveryRefused):
            store.reserve_usage_payload(
                permit, replace(delta, input_tokens=18), replace(delta, input_tokens=18).digest()
            )
        object.__setattr__(delta, "input_tokens", 99)
        with pytest.raises(RecoveryRefused):
            store.apply_usage_delta(permit, delta, delta.digest())
        assert db.get_session(scope.session_id)["input_tokens"] == 0
        original = replace(delta, input_tokens=17)
        store.apply_usage_delta(permit, original, original.digest())
        assert _read_all(store, scope)[0].delta == original
    finally:
        db.close()


@pytest.mark.parametrize(
    "tamper",
    [None, b'{"attempt_id":"duplicate","attempt_id":"duplicate"}', b"\xff", b"{}", b"unknown"],
)
def test_missing_or_corrupt_retained_bytes_refuse_apply_and_read(tmp_path: Path, tamper: bytes | None) -> None:
    db, store, scope, _, send, permit = _pending_send(tmp_path)
    delta = _delta(send)
    try:
        store.reserve_usage_payload(permit, delta, delta.digest())
        if tamper == b"unknown":
            changed = json.loads(delta.canonical_bytes())
            changed["unexpected"] = 1
            tamper = json.dumps(changed, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False).encode("utf-8")
        store._write(lambda conn: conn.execute(
            "UPDATE recovery_usage_slots SET payload_json=?,payload_sha256=? WHERE delta_id=?",
            (tamper, hashlib.sha256(tamper).hexdigest() if tamper is not None else delta.digest(),
             delta.write_id),
        ))
        with pytest.raises(RecoveryRefused):
            store.apply_usage_delta(permit, delta, delta.digest())
        assert db.get_session(scope.session_id)["input_tokens"] == 0
        store._write(lambda conn: conn.execute(
            "UPDATE recovery_usage_slots SET state='committed',ack_revision=2 WHERE delta_id=?",
            (delta.write_id,),
        ))
        with pytest.raises(RecoveryRefused):
            _read_all(store, scope)
    finally:
        db.close()


def test_reader_yields_one_row_before_refusing_oversized_later_blob(tmp_path: Path) -> None:
    db, store, scope, registry, first_send, first_permit = _pending_send(tmp_path)

    def _second_invoke():
        send = registry.sends.begin(registry.permit, "attempt-second")
        send.invoke(lambda: None)
        return send

    second_send = registry.enter(registry.permit, "sdk").run(_second_invoke)
    second_permit = issue_usage_write_permit(store, second_send.completion)
    try:
        for send, permit in ((first_send, first_permit), (second_send, second_permit)):
            delta = _delta(send)
            store.reserve_usage_payload(permit, delta, delta.digest())
            store.apply_usage_delta(permit, delta, delta.digest())
            send.finish(SendOutcome(
                kind="accounted", attempt_id=send.attempt_id,
                acknowledged_delta_ids=(send.delta_id,),
            ))
        store._write(lambda conn: conn.execute(
            "UPDATE recovery_usage_slots SET payload_json=zeroblob(10000000) WHERE delta_id=?",
            (second_send.delta_id,),
        ))

        def _inspect(conn):
            reader = store.iter_committed_usage_payloads(scope, conn=conn)
            try:
                first = next(reader)
                assert first.delta.write_id == first_send.delta_id
                with pytest.raises(RecoveryRefused, match="invalid_retained_usage_payload"):
                    next(reader)
            finally:
                reader.close()

        store._write(_inspect)
    finally:
        db.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"generation": True},
        {"input_tokens": True},
        {"input_tokens": -1},
        {"input_tokens": 2**63},
        {"api_call_count": True},
        {"estimated_cost_usd": float("nan")},
        {"actual_cost_usd": float("inf")},
        {"actual_cost_usd": -0.1},
        {"cost_source": 7},
        {"model": "x" * 4097},
        {"write_id": "x" * 256},
    ],
)
def test_invalid_scalar_refuses_before_usage_slot_reservation(tmp_path: Path, overrides) -> None:
    db, _, _, _, send, permit = _pending_send(tmp_path)
    try:
        with pytest.raises(RecoveryRefused):
            db.queue_recovery_usage(permit, _delta(send, **overrides))
        row = db._read_one(
            "SELECT payload_sha256,payload_json FROM recovery_usage_slots WHERE delta_id=?",
            (send.delta_id,),
        )
        assert tuple(row) == (None, None)
    finally:
        db.close()


def test_canonical_utf8_byte_cap_is_exact(tmp_path: Path) -> None:
    db, _, _, _, send, permit = _pending_send(tmp_path)
    try:
        base = _delta(
            send,
            model="😀" * 4096,
            billing_provider="😀" * 4096,
            billing_base_url="😀" * 4096,
            cost_source="",
        )
        needed = 65536 - len(base.canonical_bytes())
        emoji, ascii_tail = divmod(needed, 4)
        assert emoji + ascii_tail <= 4096
        exact = replace(base, cost_source="😀" * emoji + "a" * ascii_tail)
        assert len(exact.canonical_bytes()) == 65536
        assert len(exact.digest()) == 64
        with pytest.raises(RecoveryRefused):
            db.queue_recovery_usage(permit, replace(exact, cost_source=exact.cost_source + "b"))
        row = db._read_one(
            "SELECT payload_sha256,payload_json FROM recovery_usage_slots WHERE delta_id=?",
            (send.delta_id,),
        )
        assert tuple(row) == (None, None)
        assert db.queue_recovery_usage(permit, exact) == send.delta_id
        assert db.wait_recovery_write_ack(
            RecoveryScope(RecoveryStore(db).store_id, "factory", "b" * 64, "protected-session"),
            send.delta_id, timeout=5,
        ).state == "committed"
    finally:
        db.close()
