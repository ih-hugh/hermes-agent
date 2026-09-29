"""Same-owner provider identity survives transport pruning without heavy run retention."""

from __future__ import annotations

import asyncio
import weakref

import pytest

from agent.recovery_context import current_incarnation
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from gateway.platforms import api_server_runs
from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
from hermes_state import SessionDB
from hermes_state_recovery import AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore
from hermes_state_recovery_provider import capture_selected_provider_admission
from tests.recovery_provider_fixture import selected_provider


def test_selected_provider_capture_passes_exact_optional_fork_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = selected_provider(monkeypatch)
    original = provider.capture_recovery_admission
    observed: list[float] = []

    def capture(session_id: str, *, deadline: float):
        observed.append(deadline)
        return original(session_id)

    monkeypatch.setattr(provider, "capture_recovery_admission", capture)
    selected = capture_selected_provider_admission("exact-session", deadline=1234.5)
    assert selected.provider is provider
    assert observed == [1234.5]


def test_selected_provider_reacquired_after_transport_prune_and_replacement_refused(
    tmp_path, monkeypatch,
):
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    provider = selected_provider(monkeypatch, session_id="protected-session")
    capture = capture_selected_provider_admission("protected-session")
    db = SessionDB(tmp_path / "state.db")
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, "factory", "b" * 64, "protected-session")
    try:
        admitted = store.reserve(
            RecoveryAdmission(schema="hermes.recovery/v1", generation=0, parent_run_id=None),
            AdmissionIdentity(scope, "byf-recovery-v1:root", "a" * 64, "root",
                              current_incarnation(), capture.admission))
        assert admitted.outcome == "created"
        adapter._protected_provider_identities[scope] = (
            weakref.ref(provider), capture.admission.canonical_bytes())
        assert adapter._active_run_tasks == {}
        assert adapter._protected_run_registries == {}
        restored = api_server_runs._selected_provider_capture_for_scope(adapter, scope, store)
        assert restored.require_selected() is provider
        from tools import terminal_tool_config
        monkeypatch.setattr(
            terminal_tool_config, "_get_plugin_env_provider", lambda _name: object())
        with pytest.raises(RecoveryRefused, match="provider_selection_changed"):
            api_server_runs._selected_provider_capture_for_scope(adapter, scope, store)
        api_server_runs._retire_selected_provider_identity(adapter, scope)
        with pytest.raises(RecoveryRefused, match="provider_identity_unavailable"):
            api_server_runs._selected_provider_capture_for_scope(adapter, scope, store)
    finally:
        db.close()


def test_late_protected_callback_never_falls_through_to_ordinary_scheduler():
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._protected_run_ids.add("retired-run")
    loop = asyncio.new_event_loop()
    called = []
    try:
        with pytest.raises(RecoveryRefused, match="producer_closed"):
            api_server_runs._schedule_run_callback(
                adapter, "retired-run", loop, lambda: called.append(True))
        assert called == []
    finally:
        loop.close()
