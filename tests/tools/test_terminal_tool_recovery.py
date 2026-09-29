"""Physical selected-provider calls are inventoried before their side effects."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

from agent.recovery_producers import ProducerRegistry
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission, SealRequest
from hermes_state import SessionDB
from hermes_state_recovery import (
    AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore, membership_sha256,
)
from hermes_state_recovery_provider import SelectedProviderCapture
from agent.recovery_context import current_incarnation, issue_producer_permit
from tests.recovery_provider_fixture import provider_admission


def _setup(tmp_path: Path):
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    admitted = store.reserve(
        RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
        AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "root",
                          current_incarnation(), provider_admission(scope.session_id)))
    registry = ProducerRegistry(
        store, scope, "root", 0, issue_producer_permit(store, admitted.handoff))
    return db, store, scope, registry


@pytest.mark.parametrize("uncertain_result", [None, {"returncode": 1, "exit_code": 2},
                                            {"returncode": False, "exit_code": False}])
def test_selected_create_and_execute_are_inventoried_before_each_effect(
    tmp_path, monkeypatch, uncertain_result,
):
    from tools.terminal_tool_backends import _create_environment
    from tools import terminal_tool_backends
    from tools import terminal_tool, terminal_tool_config

    db, store, scope, registry = _setup(tmp_path)
    admission = provider_admission(scope.session_id)
    effects = []

    class WorkspaceEnvironment:
        def __init__(self, provider):
            self._provider = provider._core
            self._reference = admission.reference
            self.cwd = "/work"
            self.timeout = 30

        def execute_recovery(self, _command, **_kwargs):
            row = db._read_one(
                "SELECT kind,state FROM recovery_provider_invocations "
                "WHERE session_id=? ORDER BY sequence DESC LIMIT 1", (scope.session_id,))
            effects.append(("execute", tuple(row)))
            return {"output": "ok", "returncode": 2, "exit_code": 2}

        def cleanup(self):
            pass

    WorkspaceEnvironment.__module__ = "byf_workspace.workspace_provider"

    class Provider:
        name = "byf_workspace"

        def __init__(self):
            self._core = object()

        def create_environment(self, **_kwargs):
            row = db._read_one(
                "SELECT kind,state FROM recovery_provider_invocations "
                "WHERE session_id=? ORDER BY sequence DESC LIMIT 1", (scope.session_id,))
            effects.append(("create", tuple(row)))
            return WorkspaceEnvironment(self)

        def read_recovery_binding_wire(self, raw):
            assert raw == admission.canonical_bytes()
            return SimpleNamespace(
                admission=SimpleNamespace(model_dump=lambda **_k: admission.model_dump(mode="json")),
                state="bound", status_state="active", container_id="container",
                container_attestation_sha256="a" * 64)

    provider = Provider()
    registry.provider_capture = SelectedProviderCapture(admission, provider)
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    monkeypatch.setattr(terminal_tool_config, "_get_plugin_env_provider", lambda _name: provider)
    monkeypatch.setattr(terminal_tool_backends, "_get_plugin_env_provider", lambda _name: provider)
    lease = registry.enter(registry.permit, "tool")
    try:
        def invoke():
            env = _create_environment(
                "byf_workspace", "", "/work", 30, task_id=scope.session_id,
                container_config={})
            env._environment.execute_recovery = None
            with pytest.raises(RecoveryRefused, match="unsupported_provider"):
                env.execute("missing strict seam")
            del env._environment.execute_recovery
            assert env.execute("false")["returncode"] == 2
            def uncertain(_command):
                raise RuntimeError("provider response lost")
            if uncertain_result is None:
                env._environment.execute_recovery = uncertain
                with pytest.raises(RuntimeError, match="response lost"):
                    env.execute("unknown")
            else:
                env._environment.execute_recovery = lambda _command: uncertain_result
                with pytest.raises(RecoveryRefused, match="provider_result_unknown"):
                    env.execute("unknown")
            with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
                env.execute("retry")
        lease.run(invoke)
        rows = db._read_one(
            "SELECT COUNT(*),SUM(state='returned'),SUM(state='unknown') "
            "FROM recovery_provider_invocations")
        assert tuple(rows) == (3, 2, 1)
        assert effects == [
            ("create", ("create_environment", "invoking")),
            ("execute", ("execute", "invoking")),
        ]
        assert "untracked_producer" in db._read_one(
            "SELECT reason_codes_json FROM recovery_sessions WHERE session_id=?",
            (scope.session_id,))[0]
    finally:
        db.close()


def test_root_cleanup_then_nudge_reattaches_without_second_create(tmp_path, monkeypatch):
    from tools.terminal_tool_recovery import build_protected_plugin_env
    from tools import terminal_tool, terminal_tool_config

    db, store, scope, root_registry = _setup(tmp_path)
    admission = provider_admission(scope.session_id)

    class WorkspaceEnvironment:
        def __init__(self, core):
            self._provider = core
            self._reference = admission.reference
            self.cwd, self.timeout = "/work", 30
            self.detached = False

        def execute(self, _command, **_kwargs):
            assert not self.detached
            return {"returncode": 0, "exit_code": 0}

        execute_recovery = execute

        def cleanup(self, *, force_remove=False):
            self.detached = True

    WorkspaceEnvironment.__module__ = "byf_workspace.workspace_provider"

    class Provider:
        name = "byf_workspace"

        def __init__(self):
            self._core = object()
            self.creates = 0
            self.attaches = 0

        def create_environment(self, **_kwargs):
            self.creates += 1
            return WorkspaceEnvironment(self._core)

        def read_recovery_binding_wire(self, _raw):
            return SimpleNamespace(
                admission=SimpleNamespace(model_dump=lambda **_k: admission.model_dump(mode="json")),
                state="bound", status_state="active", container_id="container",
                container_attestation_sha256="a" * 64)

        def attach_recovery_environment(self, _raw, *, timeout):
            self.attaches += 1
            assert timeout == 30
            return WorkspaceEnvironment(self._core), self.read_recovery_binding_wire(_raw)

    provider = Provider()
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    monkeypatch.setattr(terminal_tool_config, "_get_plugin_env_provider", lambda _name: provider)

    def build():
        return build_protected_plugin_env(
            provider, task_id=scope.session_id, cwd="/work", timeout=30,
            image="", container_config={})

    root_registry.provider_capture = SelectedProviderCapture(admission, provider)
    root_lease = root_registry.enter(root_registry.permit, "tool")
    try:
        root_env = root_lease.run(build)
        root_env.cleanup()
        root_registry.request_close()
        nudge = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=1, parent_run_id="root"),
            AdmissionIdentity(scope, "byf-recovery-v1:nudge", "c" * 64, "nudge",
                              current_incarnation(), admission))
        assert nudge.outcome == "created"
        nudge_registry = ProducerRegistry(
            store, scope, "nudge", 1, issue_producer_permit(store, nudge.handoff))
        nudge_registry.provider_capture = SelectedProviderCapture(admission, provider)
        nudge_lease = nudge_registry.enter(nudge_registry.permit, "tool")
        nudge_lease.run(lambda: build().execute("true"))
        assert (provider.creates, provider.attaches) == (1, 1)
        rows = list(__import__("hermes_state_recovery_provider").ProviderLedger(store).rows(scope))
        assert [(row.kind, row.generation) for row in rows] == [
            ("create_environment", 0), ("execute", 1)]
        assert rows[1].create_invocation_id == rows[0].invocation_id
    finally:
        db.close()


def test_close_after_create_begin_allows_settlement_but_refuses_new_effect(
    tmp_path, monkeypatch,
):
    from tools.terminal_tool_recovery import build_protected_plugin_env
    from tools import terminal_tool, terminal_tool_config

    db, store, scope, registry = _setup(tmp_path)
    admission = provider_admission(scope.session_id)
    entered, release = threading.Event(), threading.Event()

    class WorkspaceEnvironment:
        def __init__(self, core):
            self._provider, self._reference = core, admission.reference
            self.cwd, self.timeout = "/work", 30

        def execute(self, _command):
            raise AssertionError("closing must refuse before execute")

        execute_recovery = execute

    WorkspaceEnvironment.__module__ = "byf_workspace.workspace_provider"

    class Provider:
        name = "byf_workspace"

        def __init__(self):
            self._core = object()
            self.calls = 0

        def create_environment(self, **_kwargs):
            self.calls += 1
            entered.set()
            assert release.wait(5)
            return WorkspaceEnvironment(self._core)

        def read_recovery_binding_wire(self, _raw):
            return SimpleNamespace(
                admission=SimpleNamespace(model_dump=lambda **_k: admission.model_dump(mode="json")),
                state="bound", status_state="active", container_id="container",
                container_attestation_sha256="a" * 64)

    provider = Provider()
    registry.provider_capture = SelectedProviderCapture(admission, provider)
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    monkeypatch.setattr(terminal_tool_config, "_get_plugin_env_provider", lambda _name: provider)
    lease = registry.enter(registry.permit, "tool")
    outcome: list[object] = []

    def worker():
        try:
            def body():
                env = build_protected_plugin_env(
                    provider, task_id=scope.session_id, cwd="/work", timeout=30,
                    image="", container_config={})
                with pytest.raises(RecoveryRefused, match="session_closing"):
                    env.execute("forbidden")
            lease.run(body)
            outcome.append("settled")
        except BaseException as exc:
            outcome.append(exc)

    thread = threading.Thread(target=worker)
    try:
        thread.start()
        assert entered.wait(5)
        assert db._read_one(
            "SELECT state FROM recovery_provider_invocations WHERE session_id=?",
            (scope.session_id,))[0] == "invoking"
        request = SealRequest(
            request_id="00000000-0000-4000-8000-000000000001",
            session_id=scope.session_id, run_ids=("root",),
            expected_membership_sha256=membership_sha256(("root",)))
        assert store.begin_close(scope, request).phase == "closing"
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert outcome == ["settled"]
        assert provider.calls == 1
        assert db._read_one(
            "SELECT state FROM recovery_provider_invocations WHERE session_id=?",
            (scope.session_id,))[0] == "returned"
    finally:
        release.set()
        thread.join(5)
        db.close()


def test_protected_host_background_prompt_and_guard_fallback_refuse_before_effect(
    tmp_path, monkeypatch,
):
    from tools import terminal_tool, terminal_tool_guards
    from agent import prompt_builder

    db, _store, scope, registry = _setup(tmp_path)
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    monkeypatch.setattr(prompt_builder, "_run_backend_probe", lambda *_: pytest.fail(
        "prompt probe must not create a workspace"))
    lease = registry.enter(registry.permit, "tool")
    effects = []

    class Probe:
        def execute(self, *_args, **_kwargs):
            effects.append("remote-read")
            raise RecoveryRefused("provider_result_unknown")

    try:
        def body():
            assert prompt_builder._probe_remote_backend("byf_workspace") is None
            for background, host in ((True, False), (False, True)):
                with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
                    terminal_tool._plan_execution(
                        "pwd", task_id=scope.session_id, timeout=30,
                        background=background, _host_local=host)
            with pytest.raises(RecoveryRefused, match="provider_result_unknown"):
                terminal_tool_guards._read_script_for_guard(
                    Probe(), "/work", "/work/test.sh", 100)
        lease.run(body)
        assert effects == ["remote-read"]
    finally:
        db.close()


def test_foreign_cached_environment_and_public_background_path_refuse(
    tmp_path, monkeypatch,
):
    from tools import terminal_tool
    from tools.terminal_tool_lifecycle import get_active_env

    db, _store, scope, registry = _setup(tmp_path)
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    lease = registry.enter(registry.permit, "tool")
    foreign = SimpleNamespace(cwd="/work", execute=lambda *_a, **_k: pytest.fail(
        "foreign cache must not execute"))
    try:
        with terminal_tool._env_lock:
            terminal_tool._active_environments[scope.session_id] = foreign
        def body():
            with pytest.raises(RecoveryRefused, match="provider_environment_mismatch"):
                get_active_env(scope.session_id)
            with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
                terminal_tool.terminal_tool(
                    "pwd", task_id=scope.session_id, background=True)
        lease.run(body)
    finally:
        with terminal_tool._env_lock:
            terminal_tool._active_environments.pop(scope.session_id, None)
        db.close()
