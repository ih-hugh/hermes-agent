"""The TUI observes update policy before exiting its current session."""
from __future__ import annotations

import pytest


@pytest.mark.parametrize("protected", [False, True])
def test_rpc_update_policy_identifies_backend_installation_without_session_or_process_effects(tmp_path, monkeypatch, protected):
    from tui_gateway import server
    code = tmp_path / "code"
    (code / "tui_gateway").mkdir(parents=True)
    if protected:
        (code / ".hermes-self-update-disabled").touch()
    monkeypatch.setattr(server, "__file__", str(code / "tui_gateway" / "server.py"))
    monkeypatch.setenv("HERMES_MANAGED", "false")
    monkeypatch.setattr("hermes_cli.image_provenance.IMAGE_PROVENANCE_PATH", tmp_path / "absent-image.json")
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: "git")
    response = server.dispatch({"id": "policy", "method": "system.updatePolicy", "params": {}})
    assert "error" not in response
    result = response["result"]
    assert result["schema"] == "hermes.update-policy/v1"
    assert result["installation_root"] == str(code.resolve())
    assert result["allowed"] is (not protected)
    assert result["code"] == ("self-update-disabled" if protected else None)
    assert not (tmp_path / ".update_pending.json").exists()
