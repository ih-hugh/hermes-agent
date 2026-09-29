"""Provider authority is durable, bounded and tied to the current physical lease."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent.recovery_context import current_incarnation, issue_producer_permit
from agent.recovery_producers import ProducerRegistry
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore, membership_sha256,
)
from hermes_state_recovery_provider import (
    ProviderAdmissionValue, ProviderInvocationOutcome, ProviderInvocationPermit, ProviderLedger,
    capture_selected_provider_admission,
)
from tests.recovery_provider_fixture import provider_admission, selected_provider


def _setup(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "root",
                          current_incarnation(), provider_admission(scope.session_id)),
    )
    assert admitted.outcome == "created"
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff))
    return db, store, scope, registry


def test_root_admission_atomic_and_nudge_exact(tmp_path):
    db, store, scope, registry = _setup(tmp_path)
    try:
        ledger = ProviderLedger(store)
        assert ledger.admission(scope) == provider_admission(scope.session_id)
        assert db._read_one("SELECT count(*) FROM recovery_provider_admissions")[0] == 1
        assert store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
            AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "other",
                              current_incarnation(), provider_admission(scope.session_id)),
        ).outcome == "replayed"
        registry.request_close()
        wrong = provider_admission(scope.session_id).model_copy(update={"source_sha256": "6" * 64})
        nudge = RecoveryAdmission(schema="hermes.recovery/v1", generation=1, parent_run_id="root")
        mismatch = store.reserve(nudge, AdmissionIdentity(
            scope, "byf-recovery-v1:nudge", "c" * 64, "nudge", current_incarnation(), wrong))
        assert mismatch.outcome == "refused"
        assert mismatch.reason == "provider_admission_mismatch"
        assert db._read_one("SELECT 1 FROM recovery_members WHERE run_id='nudge'") is None
        accepted = store.reserve(nudge, AdmissionIdentity(
            scope, "byf-recovery-v1:nudge", "c" * 64, "nudge", current_incarnation(),
            provider_admission(scope.session_id)))
        assert accepted.outcome == "created"
        assert ledger.admission(scope) == provider_admission(scope.session_id)
    finally:
        db.close()


def test_missing_or_corrupt_attestation_refuses(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    root = RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None)
    try:
        bad = store.reserve(root, AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(), None))
        assert (bad.outcome, bad.reason) == ("refused", "provider_admission_invalid")
        assert db._read_one("SELECT 1 FROM recovery_sessions WHERE session_id=?", (scope.session_id,)) is None
        with pytest.raises(ValueError):
            ProviderAdmissionValue.model_validate({**provider_admission(scope.session_id).model_dump(),
                                                    "provider_sha256": "7" * 64})
        admitted = store.reserve(root, AdmissionIdentity(
            scope, "byf-recovery-v1:root", "a" * 64, "root", current_incarnation(),
            provider_admission(scope.session_id)))
        assert admitted.outcome == "created"
        store._write(lambda conn: conn.execute(
            "UPDATE recovery_provider_admissions SET admission_json=? WHERE session_id=?",
            (b"x" * 4097, scope.session_id)))
        with pytest.raises(RecoveryRefused, match="provider_admission_invalid"):
            ProviderLedger(store).admission(scope)
    finally:
        db.close()


def test_invocations_require_running_lease_and_settle_exactly(tmp_path):
    db, store, scope, registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    lease = registry.enter(registry.permit, "tool")
    try:
        with pytest.raises(RecoveryRefused, match="invalid_provider_lease"):
            ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")

        def physical():
            create = ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            assert ledger.rows(scope).__next__().state == "invoking"
            with pytest.raises(RecoveryRefused, match="provider_create_conflict"):
                ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            with pytest.raises(RecoveryRefused, match="provider_create_missing"):
                ledger.begin(scope, "root", 0, lease.producer_id, "execute", create.invocation_id)
            with pytest.raises(TypeError):
                ProviderInvocationPermit(object(), create.invocation_id)
            with pytest.raises(TypeError):
                import pickle
                pickle.dumps(create)
            ledger.finish(create, ProviderInvocationOutcome(
                "returned", container_id="container-1", container_attestation_sha256="a" * 64))
            with pytest.raises(RecoveryRefused, match="invalid_provider_permit"):
                ledger.finish(create, ProviderInvocationOutcome(
                    "returned", container_id="container-1", container_attestation_sha256="a" * 64))
            execute = ledger.begin(scope, "root", 0, lease.producer_id, "execute", create.invocation_id)
            ledger.finish(execute, ProviderInvocationOutcome("returned", exit_code=2))
            rows = list(ledger.rows(scope))
            assert [(row.sequence, row.kind, row.state) for row in rows] == [
                (0, "create_environment", "returned"), (1, "execute", "returned")]
            assert rows[1].create_invocation_id == rows[0].invocation_id
            assert rows[1].exit_code == 2

        lease.run(physical)
        assert db._read_one("SELECT COUNT(*) FROM recovery_provider_invocations")[0] == 2
    finally:
        db.close()


def test_crash_and_unknown_are_retained(tmp_path):
    db, store, scope, registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    lease = registry.enter(registry.permit, "tool")
    try:
        def physical():
            started = ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            assert started.invocation_id
            # An uncaught physical exception loses the capability; the invoking
            # row remains durable and cannot be declared unused by a finalizer.

        lease.run(physical)
        assert list(ledger.rows(scope))[0].state == "invoking"
        assert db._read_one("SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
                            (scope.session_id,))[0] == "[]"
    finally:
        db.close()

    db2, store2, scope2, registry2 = _setup(tmp_path / "second")
    ledger2 = ProviderLedger(store2)
    lease2 = registry2.enter(registry2.permit, "tool")
    try:
        def physical_unknown():
            started = ledger2.begin(scope2, "root", 0, lease2.producer_id, "create_environment")
            ledger2.finish(started, ProviderInvocationOutcome("unknown", reason="provider_exception"))
        lease2.run(physical_unknown)
        assert list(ledger2.rows(scope2))[0].state == "unknown"
        assert "untracked_producer" in db2._read_one(
            "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
            (scope2.session_id,))[0]
    finally:
        db2.close()


def test_closing_stops_new_effects_but_settles_started_call(tmp_path):
    db, store, scope, registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    lease = registry.enter(registry.permit, "tool")
    try:
        def physical():
            started = ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            request = SealRequest(
                request_id="00000000-0000-4000-8000-000000000001",
                session_id=scope.session_id, run_ids=("root",),
                expected_membership_sha256=membership_sha256(("root",)))
            assert store.begin_close(scope, request).phase == "closing"
            with pytest.raises(RecoveryRefused, match="session_closing"):
                ledger.begin(scope, "root", 0, lease.producer_id, "execute", started.invocation_id)
            ledger.finish(started, ProviderInvocationOutcome(
                "returned", container_id="container-1", container_attestation_sha256="a" * 64))
        lease.run(physical)
        assert list(ledger.rows(scope))[0].state == "returned"
    finally:
        db.close()


def test_root_and_nudge_share_invocation_sequence(tmp_path):
    db, store, scope, root_registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    root_lease = root_registry.enter(root_registry.permit, "tool")
    try:
        def create():
            cap = ledger.begin(scope, "root", 0, root_lease.producer_id, "create_environment")
            ledger.finish(cap, ProviderInvocationOutcome(
                "returned", container_id="container-1", container_attestation_sha256="a" * 64))
            return cap.invocation_id
        create_id = root_lease.run(create)
        root_registry.request_close()
        admitted = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=1, parent_run_id="root"),
            AdmissionIdentity(scope, "byf-recovery-v1:nudge", "c" * 64, "nudge",
                              current_incarnation(), provider_admission(scope.session_id)))
        assert admitted.outcome == "created"
        nudge_registry = ProducerRegistry(
            store, scope, "nudge", 1, issue_producer_permit(store, admitted.handoff))
        nudge_lease = nudge_registry.enter(nudge_registry.permit, "tool")

        def execute():
            cap = ledger.begin(scope, "nudge", 1, nudge_lease.producer_id, "execute", create_id)
            ledger.finish(cap, ProviderInvocationOutcome("returned", exit_code=0))
        nudge_lease.run(execute)
        assert [(row.sequence, row.generation, row.kind) for row in ledger.rows(scope)] == [
            (0, 0, "create_environment"), (1, 1, "execute")]
    finally:
        db.close()


def test_quota_refuses_before_another_physical_effect(tmp_path, monkeypatch):
    import hermes_state_recovery_provider as provider_module

    assert provider_module.MAX_INVOCATIONS == 16_384
    db, store, scope, registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    lease = registry.enter(registry.permit, "tool")
    effects: list[str] = []
    try:
        def physical():
            create = ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            ledger.finish(create, ProviderInvocationOutcome(
                "returned", container_id="container-1", container_attestation_sha256="a" * 64))
            monkeypatch.setattr(provider_module, "MAX_INVOCATIONS", 1)
            def attempt_execute():
                ledger.begin(scope, "root", 0, lease.producer_id, "execute", create.invocation_id)
                effects.append("execute")
            with pytest.raises(RecoveryRefused, match="provider_invocation_quota"):
                attempt_execute()
            assert effects == []
        lease.run(physical)
        assert len(list(ledger.rows(scope))) == 1
    finally:
        db.close()


def test_mutated_capability_cannot_settle_another_same_lease_invocation(tmp_path):
    db, store, scope, registry = _setup(tmp_path)
    ledger = ProviderLedger(store)
    lease = registry.enter(registry.permit, "tool")
    try:
        def physical():
            create = ledger.begin(scope, "root", 0, lease.producer_id, "create_environment")
            ledger.finish(create, ProviderInvocationOutcome(
                "returned", container_id="container-1", container_attestation_sha256="a" * 64))
            first = ledger.begin(scope, "root", 0, lease.producer_id, "execute", create.invocation_id)
            second = ledger.begin(scope, "root", 0, lease.producer_id, "execute", create.invocation_id)
            first_id = first.invocation_id
            first._invocation_id = second.invocation_id
            with pytest.raises(RecoveryRefused, match="invalid_provider_permit"):
                ledger.finish(first, ProviderInvocationOutcome("returned", exit_code=0))
            assert [row.state for row in ledger.rows(scope)] == ["returned", "invoking", "invoking"]
            first._invocation_id = first_id
            ledger.finish(first, ProviderInvocationOutcome("returned", exit_code=1))
            ledger.finish(second, ProviderInvocationOutcome("returned", exit_code=0))
        lease.run(physical)
    finally:
        db.close()


def test_raw_connections_cannot_mutate_provider_ledger(tmp_path):
    db, store, scope, _registry = _setup(tmp_path)
    try:
        conn = sqlite3.connect(tmp_path / "state.db")
        try:
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM recovery_provider_admissions WHERE session_id=?",
                             (scope.session_id,))
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute("INSERT INTO recovery_provider_invocations"
                             "(invocation_id,session_id,run_id,generation,producer_id,sequence,kind,state)"
                             " VALUES('fake',?,'root',0,'fake',0,'execute','returned')",
                             (scope.session_id,))
        finally:
            conn.close()
    finally:
        db.close()


def test_capture_retains_exact_selected_object(monkeypatch):
    provider = selected_provider(monkeypatch, session_id="protected-session")
    capture = capture_selected_provider_admission("protected-session")
    assert capture.admission == provider_admission("protected-session")
    assert capture.require_selected() is provider
    from tools import terminal_tool_config
    monkeypatch.setattr(terminal_tool_config, "_get_plugin_env_provider", lambda _env: object())
    with pytest.raises(RecoveryRefused, match="provider_selection_changed"):
        capture.require_selected()
