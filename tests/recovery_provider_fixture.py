"""Synthetic, non-live source-bound provider evidence for scratch recovery tests."""

from __future__ import annotations

from hermes_state_recovery_provider import ProviderAdmissionValue


def provider_admission(session_id: str) -> ProviderAdmissionValue:
    return ProviderAdmissionValue.model_validate({
        "provider": "byf_workspace",
        "session_id": session_id,
        "hermes_revision": "1" * 40,
        "source_sha256": "2" * 64,
        "provider_sha256": "3" * 64,
        "reference": {
            "lease_id": "4" * 64,
            "grant_sha256": "5" * 64,
            "provider_sha256": "3" * 64,
        },
    })


def selected_provider(monkeypatch, *, session_id: str = "exact-session",
                      events: list[str] | None = None,
                      threads: list[int] | None = None):
    """Install a fake selected plugin whose capture returns an F-shaped typed value."""
    from tools import terminal_tool, terminal_tool_config
    from agent.terminal_env_provider import TerminalEnvironmentProvider
    import threading

    class RecoveryProviderAdmission(ProviderAdmissionValue):
        pass
    RecoveryProviderAdmission.__module__ = "byf_workspace.workspace_recovery"

    class ByfWorkspaceProvider(TerminalEnvironmentProvider):
        name = "byf_workspace"

        def is_available(self) -> bool:
            return True

        def create_environment(self, **kwargs):
            raise AssertionError("test admission cannot create a real environment")

        def capture_recovery_admission(self, requested_session: str):
            if events is not None:
                events.append("capture")
            if threads is not None:
                threads.append(threading.get_ident())
            assert requested_session == session_id
            return RecoveryProviderAdmission.model_validate(
                provider_admission(requested_session).model_dump(mode="json"))

    ByfWorkspaceProvider.__module__ = "byf_workspace"
    provider = ByfWorkspaceProvider()
    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: {"env_type": "byf_workspace"})
    monkeypatch.setattr(terminal_tool_config, "_get_plugin_env_provider", lambda env: provider)
    return provider
