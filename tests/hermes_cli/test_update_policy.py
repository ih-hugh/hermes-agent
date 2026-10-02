"""Read-only updater observations identify the launched code installation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_cli import main
from hermes_cli.subcommands.update import build_update_parser


def _parser():
    parser = argparse.ArgumentParser()
    build_update_parser(parser.add_subparsers(dest="command"), cmd_update=main.cmd_update)
    return parser


@pytest.mark.parametrize("kind", ["absent", "protected", "unresolved", "image", "managed"])
def test_policy_json_observes_installation_before_updater_effects(tmp_path, monkeypatch, capsys, kind):
    code = tmp_path / "code"
    if kind != "unresolved":
        code.mkdir()
    if kind == "protected":
        (code / ".hermes-self-update-disabled").write_text("private")
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_MANAGED", "true" if kind == "managed" else "false")
    monkeypatch.setattr(main, "PROJECT_ROOT", code)
    monkeypatch.setattr("hermes_cli.image_provenance.IMAGE_PROVENANCE_PATH", tmp_path / "absent-image.json")
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: "docker" if kind == "image" else "git")
    monkeypatch.setattr(main, "_install_hangup_protection", lambda **_k: pytest.fail("policy prepared updater"))
    main.cmd_update(SimpleNamespace(policy=True))
    data = json.loads(capsys.readouterr().out)
    assert data["schema"] == "hermes.update-policy/v1"
    assert data["allowed"] is (kind == "absent")
    assert data["installation_root"] == (None if kind == "unresolved" else str(code.resolve()))
    assert data["code"] == {"absent": None, "protected": "self-update-disabled", "unresolved": "self-update-guard-unavailable", "image": "docker", "managed": "managed-install"}[kind]
    assert "private" not in (data["message"] or "")
    assert not home.exists()


@pytest.mark.parametrize("flags", [["--force"], ["--yes"], ["--branch", "other"], ["--branch", ""], ["--check"], ["--plan"], ["--gateway"], ["--backup"], ["--no-backup"], ["--keep-stash"], ["--switch-branch"], ["--force-venv"]])
def test_policy_rejects_mutation_and_other_update_mode_flags(flags, capsys):
    parser = _parser()
    with pytest.raises(SystemExit) as error:
        args = parser.parse_args(["update", "--policy", *flags])
        args.func(args)
    assert error.value.code == 2
    assert not capsys.readouterr().out


def test_policy_flag_dispatches_read_only_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("HERMES_MANAGED", "false")
    monkeypatch.setattr("hermes_cli.image_provenance.IMAGE_PROVENANCE_PATH", tmp_path / "absent-image.json")
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: "git")
    args = _parser().parse_args(["update", "--policy"])
    args.func(args)
    assert json.loads(capsys.readouterr().out)["allowed"] is True
