"""Installation protection must precede direct Desktop helper effects."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
POSIX = ROOT / "scripts" / "desktop-update" / "posix.sh"
WINDOWS = ROOT / "scripts" / "desktop-update" / "windows.ps1"
MARKER = ".hermes-self-update-disabled"


def _protected_install(tmp_path: Path, kind: str) -> Path:
    install = tmp_path / "home" / "hermes-agent"
    install.mkdir(parents=True)
    marker = install / MARKER
    if kind == "directory":
        marker.mkdir()
    elif kind == "dangling":
        marker.symlink_to("missing")
    elif kind == "fifo":
        os.mkfifo(marker)
    else:
        marker.write_bytes(b"\xffignore=false")
    # A broken interpreter must never be invoked or repaired before refusal.
    bin_dir = install / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python").write_text("broken interpreter")
    return install


@pytest.mark.parametrize("kind", ["file", "directory", "dangling", "fifo"])
def test_posix_refuses_before_daemon_logs_marker_result_or_python(
    tmp_path: Path, kind: str
):
    install = _protected_install(tmp_path, kind)
    home = install.parent
    result_file = home / ".hermes-update-result.json"
    result_file.write_bytes(b"existing result")
    update_marker = home / ".hermes-update-in-progress"
    update_marker.write_bytes(b"existing updater")
    alias = tmp_path / "alias"
    alias.symlink_to(install, target_is_directory=True)
    result = subprocess.run(
        ["bash", str(POSIX), "--install-root", str(alias), "--no-ui"],
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "HERMES_MANAGED": "false",
            "HERMES_HOME": str(tmp_path / "profile"),
        },
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "operator-managed maintenance" in result.stderr
    assert not (home / "logs").exists()
    assert result_file.read_bytes() == b"existing result"
    assert update_marker.read_bytes() == b"existing updater"
    assert (install / "venv" / "bin" / "python").read_text() == "broken interpreter"


def test_posix_missing_root_refuses_before_effects(tmp_path: Path):
    existing = set(tmp_path.iterdir())
    result = subprocess.run(
        ["bash", str(POSIX), "--install-root", str(tmp_path / "missing"), "--no-ui"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "operator-managed maintenance" in result.stderr
    assert set(tmp_path.iterdir()) == existing


def test_posix_unmarked_install_keeps_repair_selftest_available(tmp_path: Path):
    install = tmp_path / "install"
    (install / "venv" / "bin").mkdir(parents=True)
    result = subprocess.run(
        ["bash", str(POSIX), "--install-root", str(install), "--self-test-tcc-heal"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "state=" in result.stdout


def _repairable_install(tmp_path: Path) -> Path:
    install = tmp_path / "home" / "hermes-agent"
    bin_dir = install / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    python = bin_dir / "python"
    python.write_text("#!/bin/sh\nexit 1\n")
    python.chmod(0o700)
    for name in ("python3", "python3.12"):
        (bin_dir / name).symlink_to("python")
    source = tmp_path / "store-python"
    source.symlink_to(sys.executable)
    (bin_dir / ".tcc-anchor-source").write_text(str(source))
    return install


def _venv_entries(install: Path) -> dict[str, bytes | str]:
    return {
        entry.name: os.readlink(entry) if entry.is_symlink() else entry.read_bytes()
        for entry in (install / "venv" / "bin").iterdir()
    }


def _assert_protected_repair_refusal(install: Path, flags: list[str]) -> None:
    home = install.parent
    result_file = home / ".hermes-update-result.json"
    result_file.write_bytes(b"existing result")
    update_marker = home / ".hermes-update-in-progress"
    update_marker.write_bytes(b"existing updater")
    before = _venv_entries(install)
    alias = home.parent / "install-alias"
    alias.symlink_to(install, target_is_directory=True)
    result = subprocess.run(
        ["bash", str(POSIX), "--install-root", str(alias), "--no-ui", *flags],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "operator-managed maintenance" in result.stderr
    assert _venv_entries(install) == before
    assert not (home / "logs").exists()
    assert result_file.read_bytes() == b"existing result"
    assert update_marker.read_bytes() == b"existing updater"
    assert alias.is_symlink() and alias.resolve() == install


@pytest.mark.macos_only
@pytest.mark.parametrize("exempt_mode", ["--self-test-ui", "--self-test-gate"])
def test_posix_mixed_selftest_modes_cannot_repair_protected_venv(
    tmp_path: Path, exempt_mode: str
):
    install = _repairable_install(tmp_path)
    (install / MARKER).write_bytes(b"protected")
    _assert_protected_repair_refusal(install, [exempt_mode, "--self-test-tcc-heal"])


@pytest.mark.macos_only
def test_posix_case_insensitive_marker_lookup_refuses_before_repair(tmp_path: Path):
    install = _repairable_install(tmp_path)
    variant = install / ".HERMES-self-update-disabled"
    variant.write_bytes(b"protected")
    literal = install / MARKER
    if not literal.exists():
        pytest.skip("requires a native case-insensitive scratch filesystem")
    assert literal.samefile(variant)
    _assert_protected_repair_refusal(install, ["--self-test-tcc-heal"])


@pytest.mark.linux_only
def test_posix_case_sensitive_non_marker_keeps_unmarked_repair(tmp_path: Path):
    install = _repairable_install(tmp_path)
    (install / ".HERMES-self-update-disabled").write_bytes(b"other entry")
    if (install / MARKER).exists():
        pytest.skip("requires a native case-sensitive scratch filesystem")
    result = subprocess.run(
        ["bash", str(POSIX), "--install-root", str(install), "--self-test-tcc-heal"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "state=healed-symlinks" in result.stdout
    assert (install / "venv" / "bin" / "python").is_symlink()


@pytest.mark.macos_only
def test_posix_inaccessible_root_refuses_without_python(tmp_path: Path):
    install = tmp_path / "denied"
    install.mkdir()
    install.chmod(0)
    try:
        result = subprocess.run(
            ["bash", str(POSIX), "--install-root", str(install), "--no-ui"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 2
        assert "operator-managed maintenance" in result.stderr
        assert not (tmp_path / "logs").exists()
    finally:
        install.chmod(0o700)


@pytest.mark.windows_only
@pytest.mark.parametrize("forwarder", [False, True])
def test_windows_direct_and_forwarder_refuse_before_handoff(
    tmp_path: Path, forwarder: bool
):
    install = _protected_install(tmp_path, "file")
    script = ROOT / "scripts" / "desktop-update.ps1" if forwarder else WINDOWS
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-InstallRoot",
            str(install),
            "-NoUi",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "operator-managed maintenance" in result.stdout + result.stderr
    assert not (install.parent / "logs").exists()
    assert not (install.parent / ".hermes-update-in-progress").exists()
    assert not (install.parent / ".hermes-update-result.json").exists()


@pytest.mark.windows_only
def test_windows_native_junction_and_dangling_entry_keep_install_protection(
    tmp_path: Path,
):
    install = tmp_path / "install"
    install.mkdir()
    alias = tmp_path / "install-alias"
    target = tmp_path / "marker-target"
    target.mkdir()
    marker = install / MARKER
    for link, destination in [(alias, install), (marker, target)]:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(destination)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    target.rmdir()
    guard = str(ROOT / "scripts" / "desktop-update" / "installation-guard.ps1").replace(
        "'", "''"
    )
    selected = str(alias).replace("'", "''")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f". '{guard}'; Get-HermesSelfUpdateInstallation -InstallRoot '{selected}' | ConvertTo-Json -Compress",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        env={
            **os.environ,
            "HERMES_HOME": str(tmp_path / "profile"),
            "HERMES_MANAGED": "false",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert Path(observed["Root"]) == install
    assert "operator-managed maintenance" in observed["Refusal"]
    assert not (tmp_path / "logs").exists()
