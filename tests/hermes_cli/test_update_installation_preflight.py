"""Protected installations refuse before supported Python updater effects."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from hermes_cli import main, update_cmd, update_inventory


@pytest.mark.parametrize("flags", [
    {}, {"yes": True}, {"force": True, "force_venv": True},
    {"gateway": True, "branch": "other", "switch_branch": True, "no_backup": True},
    {"check": True, "branch": "other"},
])
def test_protected_cli_refuses_before_update_lock_and_preparation(tmp_path, monkeypatch, flags):
    code = tmp_path / "code"
    code.mkdir()
    (code / ".hermes-self-update-disabled").touch()
    monkeypatch.setattr(main, "PROJECT_ROOT", code)
    monkeypatch.setenv("HERMES_MANAGED", "false")
    def forbidden(*_a, **_k):
        pytest.fail("updater preparation before refusal")
    monkeypatch.setattr(main, "_install_hangup_protection", forbidden)
    monkeypatch.setattr(update_cmd, "_cmd_update_impl", forbidden)
    monkeypatch.setattr(update_cmd, "_cmd_update_check", forbidden)
    with pytest.raises(SystemExit) as error:
        main.cmd_update(SimpleNamespace(**flags))
    assert error.value.code == 2
    assert list(code.iterdir()) == [code / ".hermes-self-update-disabled"]


def test_protected_plan_is_read_only_and_not_updatable(tmp_path, monkeypatch, capsys):
    code = tmp_path / "code"
    code.mkdir()
    (code / ".hermes-self-update-disabled").touch()
    monkeypatch.setattr(main, "PROJECT_ROOT", code)
    monkeypatch.setattr("hermes_cli.config.get_project_root", lambda: code)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    monkeypatch.setenv("HERMES_MANAGED", "false")
    monkeypatch.setattr(update_inventory, "_collect_gateway_runtimes", lambda *_a: None)
    monkeypatch.setattr(update_inventory, "_collect_ledger_runtimes", lambda *_a: None)
    monkeypatch.setattr("hermes_cli.update_receipt._profile_homes", lambda: [])
    monkeypatch.setattr("hermes_cli.build_info.get_code_identity", lambda **_k: {})
    plan = update_inventory.collect_runtime_inventory()
    assert plan.updatable_in_place is False
    assert plan.update_mechanism == "operator-managed maintenance"
    main.cmd_update(SimpleNamespace(plan=True))
    assert "NOT updatable in place" in capsys.readouterr().out
    assert not (tmp_path / "profile").exists()


def test_tui_exit_update_rechecks_protection_before_relaunch(tmp_path, monkeypatch):
    from hermes_cli import main_tui_launch
    code = tmp_path / "code"
    code.mkdir()
    (code / ".hermes-self-update-disabled").touch()
    monkeypatch.setattr(main, "PROJECT_ROOT", code)
    monkeypatch.setenv("HERMES_MANAGED", "false")
    monkeypatch.setattr(main_tui_launch, "_make_tui_argv", lambda *_a: (["node", "stub"], code))
    monkeypatch.setattr(main_tui_launch.subprocess, "call", lambda *_a, **_k: 42)
    monkeypatch.setattr("hermes_cli.relaunch.relaunch", lambda *_a, **_k: pytest.fail("protected TUI update relaunched"))
    with pytest.raises(SystemExit) as error:
        main_tui_launch._launch_tui()
    assert error.value.code == 2
