"""Dashboard update routes project installation maintenance protection."""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["apply", "check"])
async def test_protected_dashboard_refuses_before_spawn_and_remote_check(tmp_path, monkeypatch, surface):
    from hermes_cli import web_server, web_server_gateway, web_server_files
    from hermes_cli.web_routers import actions
    code = tmp_path / "code"
    code.mkdir()
    (code / ".hermes-self-update-disabled").touch()
    monkeypatch.setattr(web_server, "PROJECT_ROOT", code)
    monkeypatch.setattr(web_server_gateway, "_ACTION_LOG_DIR", tmp_path / "action-logs")
    monkeypatch.setattr(web_server_files, "_dashboard_local_update_managed_externally", lambda: False)
    def forbidden(*_a, **_k):
        pytest.fail("protected dashboard updater effect")
    monkeypatch.setattr(web_server_gateway, "_spawn_hermes_action", forbidden)
    monkeypatch.setattr("hermes_cli.banner.check_for_updates", forbidden)
    monkeypatch.setenv("HERMES_MANAGED", "false")
    if surface == "apply":
        result = await actions.update_hermes()
        assert result["ok"] is False and result["pid"] is None
        assert result["error"] == "self_update_disabled"
    else:
        result = await actions.check_hermes_update(force=True)
        assert result["can_apply"] is False and result["update_available"] is False
    assert "operator-managed maintenance" in result["message"]
    assert result["update_command"] == "operator-managed maintenance"
    assert list(code.iterdir()) == [code / ".hermes-self-update-disabled"]
