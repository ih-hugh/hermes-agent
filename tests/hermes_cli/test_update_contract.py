"""Image-managed refusal contract tests (#91277 Phase 3).

Marker semantics (image_provenance.py, salvaged from #92545 @andrexibiza):
absent → None; present-and-valid → provenance; present-but-broken →
fail-closed invalid. Admission gate (update_contract.py): marker first,
docker/nix/apt heuristics second; refusals record a `refused` receipt.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermes_cli.image_provenance import read_image_provenance
from hermes_cli.update_contract import (
    UpdateRefusal,
    evaluate_update_admission,
    record_refusal_receipt,
)


def _valid_marker(tmp_path: Path) -> Path:
    marker = tmp_path / "image-provenance.json"
    marker.write_text(json.dumps({
        "schema": 1,
        "deployment_kind": "image",
        "manager": "docker",
        "image": "nousresearch/hermes-agent",
        "version": "1.0.0",
        "revision": "a" * 40,
    }))
    return marker


# ---------------------------------------------------------------------------
# Marker reader
# ---------------------------------------------------------------------------


def test_reader_absent_marker_means_none(tmp_path):
    assert read_image_provenance(tmp_path / "nope.json") is None


def test_reader_valid_marker(tmp_path):
    provenance = read_image_provenance(_valid_marker(tmp_path))
    assert provenance is not None and provenance.valid
    assert provenance.manager == "docker"
    assert provenance.version == "1.0.0"


@pytest.mark.parametrize(
    "payload,reason_prefix",
    [
        ("not json {", "marker_unreadable"),
        (json.dumps([1, 2]), "marker_not_object"),
        (json.dumps({"schema": True, "deployment_kind": "image", "manager": "docker"}), "unsupported_marker_schema"),
        (json.dumps({"schema": 2, "deployment_kind": "image", "manager": "docker"}), "unsupported_marker_schema"),
        (json.dumps({"schema": 1, "deployment_kind": "source", "manager": "docker"}), "invalid_deployment_kind"),
        (json.dumps({"schema": 1, "deployment_kind": "image", "manager": "  "}), "missing_manager"),
    ],
)
def test_reader_fails_closed_on_malformed(tmp_path, payload, reason_prefix):
    marker = tmp_path / "image-provenance.json"
    marker.write_text(payload)
    provenance = read_image_provenance(marker)
    assert provenance is not None and not provenance.valid
    assert provenance.error.startswith(reason_prefix)


def test_reader_rejects_symlink_marker(tmp_path):
    real = _valid_marker(tmp_path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    provenance = read_image_provenance(link)
    assert provenance is not None and not provenance.valid
    assert provenance.error == "marker_not_regular_file"


# ---------------------------------------------------------------------------
# Admission gate
# ---------------------------------------------------------------------------


def test_admission_marker_refuses_even_on_git_checkout(tmp_path, monkeypatch):
    """The bind-mounted-checkout case: heuristics say git, marker says image
    — the marker wins."""
    import hermes_cli.image_provenance as ip

    monkeypatch.setattr(ip, "IMAGE_PROVENANCE_PATH", _valid_marker(tmp_path))
    monkeypatch.setattr(
        "hermes_cli.config.detect_install_method", lambda *a, **k: "git"
    )
    refusal = evaluate_update_admission(tmp_path)
    assert refusal is not None
    assert refusal.code == "image-marker"
    assert "docker pull" in refusal.update_command


def test_admission_invalid_marker_fails_closed(tmp_path, monkeypatch):
    import hermes_cli.image_provenance as ip

    bad = tmp_path / "image-provenance.json"
    bad.write_text("corrupted {{{")
    monkeypatch.setattr(ip, "IMAGE_PROVENANCE_PATH", bad)
    refusal = evaluate_update_admission(tmp_path)
    assert refusal is not None
    assert refusal.code == "image-marker-invalid"
    assert "docker pull" in refusal.update_command


def test_admission_no_marker_falls_back_to_heuristics(tmp_path, monkeypatch):
    import hermes_cli.image_provenance as ip

    monkeypatch.setattr(ip, "IMAGE_PROVENANCE_PATH", tmp_path / "absent.json")
    monkeypatch.setattr(
        "hermes_cli.config.detect_install_method", lambda *a, **k: "docker"
    )
    refusal = evaluate_update_admission(tmp_path)
    assert refusal is not None and refusal.code == "docker"


def test_admission_git_checkout_no_marker_is_admitted(tmp_path, monkeypatch):
    import hermes_cli.image_provenance as ip

    monkeypatch.setattr(ip, "IMAGE_PROVENANCE_PATH", tmp_path / "absent.json")
    monkeypatch.setattr(
        "hermes_cli.config.detect_install_method", lambda *a, **k: "git"
    )
    assert evaluate_update_admission(tmp_path) is None


def test_admission_apt_and_nix_refuse(tmp_path, monkeypatch):
    import hermes_cli.image_provenance as ip

    monkeypatch.setattr(ip, "IMAGE_PROVENANCE_PATH", tmp_path / "absent.json")
    for method, code in (("apt", "apt"), ("nix", "nix")):
        def _detect(*a, _m=method, **k):
            return _m

        monkeypatch.setattr("hermes_cli.config.detect_install_method", _detect)
        refusal = evaluate_update_admission(tmp_path)
        assert refusal is not None and refusal.code == code


# ---------------------------------------------------------------------------
# Refusal receipt
# ---------------------------------------------------------------------------


def test_refusal_receipt_written_as_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import hermes_cli.update_receipt as ur

    monkeypatch.setattr(ur, "_receipt_dir", lambda: tmp_path / "receipts")

    record_refusal_receipt(
        UpdateRefusal(
            code="image-marker",
            message="msg",
            update_command="docker pull nousresearch/hermes-agent:latest",
        )
    )
    receipts = list((tmp_path / "receipts").glob("*.json"))
    receipts = [p for p in receipts if p.name != "latest.json"]
    assert receipts, "a refusal receipt must be written"
    data = json.loads(receipts[0].read_text())
    assert data["outcome"] == "refused"
    assert data["stop_reason"] == "image-marker"
    steps = {s["name"]: s for s in data["steps"]}
    assert "admission" in steps and steps["admission"]["ok"] is False
    assert "docker pull" in steps["admission"]["detail"]


@pytest.mark.parametrize("kind", ["empty", "content", "directory", "symlink", "broken-symlink"])
def test_installation_sentinel_refuses_every_entry_without_reading_content(tmp_path, monkeypatch, kind):
    marker = tmp_path / ".hermes-self-update-disabled"
    if kind == "directory":
        marker.mkdir()
    elif kind in {"symlink", "broken-symlink"}:
        target = tmp_path / "target"
        if kind == "symlink":
            target.touch()
        marker.symlink_to(target)
    else:
        marker.write_text("private marker contents" if kind == "content" else "")
    monkeypatch.setenv("HERMES_MANAGED", "false")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "other-profile"))
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: "git")
    refusal = evaluate_update_admission(tmp_path)
    assert refusal is not None and refusal.code == "self-update-disabled"
    assert "private marker contents" not in refusal.message
    assert "operator-managed maintenance" in refusal.message


@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("unavailable")])
def test_installation_lookup_uncertainty_refuses_before_legacy_fallback(tmp_path, monkeypatch, error):
    original = Path.lstat
    def uncertain(path):
        if path.name == ".hermes-self-update-disabled":
            raise error
        return original(path)
    monkeypatch.setattr(Path, "lstat", uncertain)
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: pytest.fail("legacy fallback"))
    refusal = evaluate_update_admission(tmp_path)
    assert refusal is not None and refusal.code == "self-update-guard-unavailable"


def test_installation_guard_resolves_code_root_and_refuses_resolution_failure(tmp_path, monkeypatch):
    code = tmp_path / "code"
    code.mkdir()
    (code / ".hermes-self-update-disabled").touch()
    alias = tmp_path / "alias"
    alias.symlink_to(code, target_is_directory=True)
    assert evaluate_update_admission(alias).code == "self-update-disabled"
    assert evaluate_update_admission(tmp_path / "missing").code == "self-update-guard-unavailable"


def test_disappeared_installation_is_not_definite_sentinel_absence(tmp_path, monkeypatch):
    code = tmp_path / "code"
    code.mkdir()
    original = Path.lstat
    def disappear(path):
        if path.name == ".hermes-self-update-disabled":
            code.rmdir()
        return original(path)
    monkeypatch.setattr(Path, "lstat", disappear)
    refusal = evaluate_update_admission(code)
    assert refusal is not None and refusal.code == "self-update-guard-unavailable"


def test_profile_and_cwd_markers_do_not_guard_another_code_installation(tmp_path, monkeypatch):
    code = tmp_path / "code"
    code.mkdir()
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / ".hermes-self-update-disabled").touch()
    monkeypatch.chdir(profile)
    monkeypatch.setenv("HERMES_HOME", str(profile))
    monkeypatch.setattr("hermes_cli.image_provenance.IMAGE_PROVENANCE_PATH", tmp_path / "absent-image.json")
    monkeypatch.setattr("hermes_cli.config.detect_install_method", lambda *_a, **_k: "git")
    assert evaluate_update_admission(code) is None
