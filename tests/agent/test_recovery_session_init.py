"""The actual protected agent initializes its admitted source row once."""

from __future__ import annotations

import pytest

from agent.recovery_context import (
    AdmissionHandoff,
    bind_write_permit,
    current_incarnation,
    issue_producer_permit,
    issue_write_permit,
)
from agent.recovery_producers import ProducerRegistry
from gateway.run import _profile_runtime_scope
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity,
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
)
from run_agent import AIAgent
from tests.agent.test_recovery_runtime import _admitted
from tests.recovery_provider_fixture import provider_admission


def _scratch_profile_homes(tmp_path, monkeypatch):
    from hermes_cli import profiles

    default_home = tmp_path / "hermes"
    named_home = default_home / "profiles" / "factory"
    for home in (default_home, named_home):
        home.mkdir(parents=True)
        (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(profiles, "_get_default_hermes_home", lambda: default_home)
    monkeypatch.setattr(
        profiles, "_get_profiles_root", lambda: default_home / "profiles"
    )
    return {"default": default_home, "factory": named_home}


@pytest.mark.parametrize("profile", ["default", "factory"])
def test_actual_agent_first_metadata_is_acknowledged(tmp_path, monkeypatch, profile):
    from hermes_cli import profiles

    homes = _scratch_profile_homes(tmp_path, monkeypatch)
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, profile, "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(
            schema="hermes.recovery/v1", generation=0, parent_run_id=None
        ),
        AdmissionIdentity(
            scope,
            "byf-recovery-v1:root",
            "a" * 64,
            "run_root",
            current_incarnation(),
            provider_admission(scope.session_id),
        ),
    )
    assert admitted.outcome == "created"
    assert isinstance(admitted.handoff, AdmissionHandoff)
    registry = ProducerRegistry(
        store,
        scope,
        "run_root",
        0,
        issue_producer_permit(store, admitted.handoff),
    )
    writer = issue_write_permit(registry.permit, store, scope, "run_root", 0)
    executor = registry.enter(registry.permit, "executor")

    def construct_and_persist():
        agent = AIAgent(
            api_key="scratch-only",
            base_url="http://127.0.0.1:9/v1",
            provider="openai",
            api_mode="chat_completions",
            model="gpt-4o",
            enabled_toolsets=[],
            session_id=scope.session_id,
            session_db=db,
            platform="api_server",
            quiet_mode=True,
            skip_memory=True,
            skip_background_review=True,
            skip_context_files=True,
        )
        agent._ensure_db_session()
        assert agent._session_db_created is True
        assert (
            getattr(agent, "provider") == "openai"
            and getattr(agent, "model") == "gpt-4o"
        )
        agent._ensure_db_session()

    try:
        with _profile_runtime_scope(homes[profile], prepared_secret_scope={}):
            assert profiles.get_active_profile_name() == profile
            with bind_write_permit(writer):
                executor.run(construct_and_persist)
        row = db._read_one(
            "SELECT source,profile_name,model,model_config FROM sessions WHERE id=?",
            (scope.session_id,),
        )
        assert row is not None
        assert row[:3] == ("api_server", profile, "gpt-4o")
        assert row[3] is not None
        ack = db._read_one(
            "SELECT mutation,state FROM recovery_write_acks WHERE session_id=?",
            (scope.session_id,),
        )
        assert ack is not None and tuple(ack) == ("session", "committed")
    finally:
        db.close()


def test_protected_first_metadata_stable_ack_and_nudge_reuses_root(tmp_path):
    db, store, scope, registry = _admitted(tmp_path)
    writer = issue_write_permit(registry.permit, store, scope, "run_root", 0)
    executor = registry.enter(registry.permit, "executor")

    def initialize_root():
        args = dict(
            session_id=scope.session_id,
            source="api_server",
            profile_name="factory",
            recovery_permit=writer,
            model="gpt-4o",
            model_config={"mode": "chat"},
        )
        db.initialize_protected_session(**args)
        db.initialize_protected_session(**args)  # Lost response after committed ack.
        with pytest.raises(RecoveryRefused, match="write_payload_conflict"):
            db.initialize_protected_session(**(args | {"model": "gpt-4.1"}))

    try:
        with bind_write_permit(writer):
            executor.run(initialize_root)
        registry.request_close()
        before = tuple(
            db._read_one(
                "SELECT * FROM sessions WHERE id=?",
                (scope.session_id,),
            )
        )
        assert (
            db._read_one(
                "SELECT count(*) FROM recovery_write_acks WHERE session_id=? AND state='committed'",
                (scope.session_id,),
            )[0]
            == 1
        )

        admission = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=1, parent_run_id="run_root"
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:nudge",
                "c" * 64,
                "run_nudge",
                current_incarnation(),
                provider_admission(scope.session_id),
            ),
        )
        assert admission.outcome == "created"
        assert isinstance(admission.handoff, AdmissionHandoff)
        nudge = ProducerRegistry(
            store,
            scope,
            "run_nudge",
            1,
            issue_producer_permit(store, admission.handoff),
        )
        nudge_writer = issue_write_permit(nudge.permit, store, scope, "run_nudge", 1)
        nudge_executor = nudge.enter(nudge.permit, "executor")
        with bind_write_permit(nudge_writer):
            nudge_executor.run(
                lambda: db.initialize_protected_session(
                    scope.session_id,
                    "api_server",
                    recovery_permit=nudge_writer,
                    profile_name="factory",
                    model="gpt-4.1",
                    session_key="new-route",
                )
            )
        assert (
            tuple(
                db._read_one(
                    "SELECT * FROM sessions WHERE id=?",
                    (scope.session_id,),
                )
            )
            == before
        )
        assert (
            db._read_one(
                "SELECT count(*) FROM recovery_write_acks WHERE session_id=? AND state='committed'",
                (scope.session_id,),
            )[0]
            == 2
        )
    finally:
        db.close()


def test_no_call_root_nudge_executor_performs_first_metadata_fill(
    tmp_path, monkeypatch
):
    from hermes_cli import profiles

    homes = _scratch_profile_homes(tmp_path, monkeypatch)
    db, store, scope, root_registry = _admitted(tmp_path)
    try:
        source_before = tuple(
            db._read_one(
                "SELECT id,source,profile_name,started_at FROM sessions WHERE id=?",
                (scope.session_id,),
            )
        )
        assert (
            db._read_one(
                "SELECT count(*) FROM recovery_write_acks WHERE session_id=?",
                (scope.session_id,),
            )[0]
            == 0
        )
        root_registry.request_close()  # Queued stop: no root executor or agent ran.
        admission = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=1, parent_run_id="run_root"
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:nudge-first",
                "d" * 64,
                "run_nudge",
                current_incarnation(),
                provider_admission(scope.session_id),
            ),
        )
        assert admission.outcome == "created"
        assert isinstance(admission.handoff, AdmissionHandoff)
        nudge = ProducerRegistry(
            store,
            scope,
            "run_nudge",
            1,
            issue_producer_permit(store, admission.handoff),
        )
        writer = issue_write_permit(nudge.permit, store, scope, "run_nudge", 1)
        executor = nudge.enter(nudge.permit, "executor")

        def initialize_nudge_agent():
            agent = AIAgent(
                api_key="scratch-only",
                base_url="http://127.0.0.1:9/v1",
                provider="openai",
                api_mode="chat_completions",
                model="gpt-4o",
                enabled_toolsets=[],
                session_id=scope.session_id,
                session_db=db,
                platform="api_server",
                quiet_mode=True,
                skip_memory=True,
                skip_background_review=True,
                skip_context_files=True,
            )
            agent._ensure_db_session()
            assert agent._session_db_created is True

        with _profile_runtime_scope(homes["factory"], prepared_secret_scope={}):
            assert profiles.get_active_profile_name() == "factory"
            with bind_write_permit(writer):
                executor.run(initialize_nudge_agent)
        assert (
            tuple(
                db._read_one(
                    "SELECT id,source,profile_name,started_at FROM sessions WHERE id=?",
                    (scope.session_id,),
                )
            )
            == source_before
        )
        assert (
            db._read_one(
                "SELECT model FROM sessions WHERE id=?",
                (scope.session_id,),
            )[0]
            == "gpt-4o"
        )
        ack = db._read_one(
            "SELECT run_id,state,result_json FROM recovery_write_acks WHERE session_id=?",
            (scope.session_id,),
        )
        assert ack is not None and tuple(ack) == (
            "run_nudge",
            "committed",
            '{"initialized": true}',
        )
    finally:
        db.close()


def test_protected_agent_first_metadata_failure_is_visible(tmp_path, monkeypatch):
    from hermes_cli import profiles

    db, store, scope, registry = _admitted(tmp_path)
    monkeypatch.setattr(profiles, "get_active_profile_name", lambda: "factory")
    executor = registry.enter(registry.permit, "executor")

    def construct():
        return AIAgent(
            api_key="scratch-only",
            base_url="http://127.0.0.1:9/v1",
            provider="openai",
            api_mode="chat_completions",
            model="gpt-4o",
            enabled_toolsets=[],
            session_id=scope.session_id,
            session_db=db,
            platform="api_server",
            quiet_mode=True,
            skip_memory=True,
            skip_background_review=True,
            skip_context_files=True,
        )

    try:
        writer = issue_write_permit(registry.permit, store, scope, "run_root", 0)
        with bind_write_permit(writer):
            agent = executor.run(construct)
        agent._recovery_registry = registry
        agent._persist_disabled = True
        with bind_write_permit(writer):
            with pytest.raises(RecoveryRefused, match="session_init_unavailable"):
                agent._ensure_db_session()
        agent._persist_disabled = False
        with bind_write_permit(writer):
            with pytest.raises(RecoveryRefused, match="session_init_executor_required"):
                agent._ensure_db_session()
        assert agent._session_db_created is False
        assert tuple(
            db._read_one(
                "SELECT model,model_config FROM sessions WHERE id=?",
                (scope.session_id,),
            )
        ) == (None, None)
        assert (
            db._read_one(
                "SELECT count(*) FROM recovery_write_acks WHERE session_id=?",
                (scope.session_id,),
            )[0]
            == 0
        )
    finally:
        db.close()


def test_physical_profile_mismatch_refuses_metadata_fill(tmp_path, monkeypatch):
    from hermes_cli import profiles

    homes = _scratch_profile_homes(tmp_path, monkeypatch)
    db, store, scope, registry = _admitted(tmp_path)  # Admission profile is factory.
    writer = issue_write_permit(registry.permit, store, scope, "run_root", 0)
    executor = registry.enter(registry.permit, "executor")

    def construct_and_persist():
        agent = AIAgent(
            api_key="scratch-only",
            base_url="http://127.0.0.1:9/v1",
            provider="openai",
            api_mode="chat_completions",
            model="gpt-4o",
            enabled_toolsets=[],
            session_id=scope.session_id,
            session_db=db,
            platform="api_server",
            quiet_mode=True,
            skip_memory=True,
            skip_background_review=True,
            skip_context_files=True,
        )
        with pytest.raises(RecoveryRefused, match="session_init_executor_required"):
            agent._ensure_db_session()
        assert agent._session_db_created is False

    try:
        before = tuple(
            db._read_one(
                "SELECT * FROM sessions WHERE id=?",
                (scope.session_id,),
            )
        )
        with _profile_runtime_scope(homes["default"], prepared_secret_scope={}):
            assert profiles.get_active_profile_name() == "default"
            with bind_write_permit(writer):
                executor.run(construct_and_persist)
        assert (
            tuple(
                db._read_one(
                    "SELECT * FROM sessions WHERE id=?",
                    (scope.session_id,),
                )
            )
            == before
        )
    finally:
        db.close()
