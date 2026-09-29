"""No-effect preparation of the one supported protected constructor route."""

from __future__ import annotations

from pathlib import Path

import pytest

from gateway.platforms.api_server_recovery import RecoveryOwnerContext
from hermes_state_recovery import RecoveryRefused


def _profile(
    tmp_path: Path, monkeypatch, *, model: str = "gpt-4.1"
) -> RecoveryOwnerContext:
    home = tmp_path / "profile"
    home.mkdir()
    (home / "config.yaml").write_text(
        "platforms:\n  api_server:\n    recovery:\n      enabled: true\n"
        "platform_toolsets:\n  api_server: [terminal_only, no_mcp]\n"
        "tools:\n  tool_search:\n    enabled: 'off'\n"
        "terminal:\n  backend: byf_workspace\n"
        "context:\n  engine: compressor\n"
        f"model:\n  provider: openai-api\n  api_mode: chat_completions\n  default: {model}\n"
        "  context_length: 128000\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-scratch-constructor-only")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(
        "hermes_cli.profiles.get_active_profile_name", lambda: "factory"
    )
    return RecoveryOwnerContext("factory", home, "b" * 64)


def test_static_preparation_refuses_implicit_or_redirected_route_before_provider_lookup(
    tmp_path: Path, monkeypatch
) -> None:
    from gateway.platforms.api_server_recovery_runtime import (
        prepare_static_chat_runtime,
    )
    from agent import terminal_env_registry

    owner = _profile(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        terminal_env_registry,
        "get_provider",
        lambda *_: calls.append("provider") or object(),
    )
    config = owner.home / "config.yaml"
    for old, new in (
        ("api_mode: chat_completions", "api_mode: codex_responses"),
        ("provider: openai-api", "provider: nous"),
    ):
        original = config.read_text(encoding="utf-8")
        config.write_text(original.replace(old, new), encoding="utf-8")
        with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
            prepare_static_chat_runtime(owner, session_id="protected-session")
        config.write_text(original, encoding="utf-8")
    assert calls == []


def test_static_preparation_refuses_missing_key_and_wrong_physical_home(
    tmp_path: Path, monkeypatch
) -> None:
    from gateway.platforms.api_server_recovery_runtime import (
        prepare_static_chat_runtime,
    )

    owner = _profile(tmp_path, monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
        prepare_static_chat_runtime(owner, session_id="protected-session")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-scratch-constructor-only")
    wrong = RecoveryOwnerContext(
        owner.profile, tmp_path / "different", owner.scope_digest
    )
    with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
        prepare_static_chat_runtime(wrong, session_id="protected-session")


def test_static_preparation_bounds_config_before_parsing_or_provider_lookup(
    tmp_path: Path, monkeypatch
) -> None:
    from gateway.platforms.api_server_recovery_runtime import (
        prepare_static_chat_runtime,
    )
    from agent import terminal_env_registry
    import utils

    owner = _profile(tmp_path, monkeypatch)
    (owner.home / "config.yaml").write_bytes(b"x" * (1_048_576 + 1))
    calls: list[str] = []
    monkeypatch.setattr(utils, "fast_safe_load", lambda *_: calls.append("parse"))
    monkeypatch.setattr(
        terminal_env_registry, "get_provider", lambda *_: calls.append("provider")
    )
    with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
        prepare_static_chat_runtime(owner, session_id="protected-session")
    assert calls == []


def test_static_preparation_refuses_config_changed_during_exact_parse(
    tmp_path: Path, monkeypatch
) -> None:
    from gateway.platforms.api_server_recovery_runtime import (
        prepare_static_chat_runtime,
    )
    from agent import terminal_env_registry
    import utils

    owner = _profile(tmp_path, monkeypatch)
    config = owner.home / "config.yaml"
    original_parser = utils.fast_safe_load
    calls: list[str] = []

    def parse_then_change(stream):
        result = original_parser(stream)
        content = config.read_text(encoding="utf-8")
        config.write_text(content.replace("gpt-4.1", "gpt-4.2"), encoding="utf-8")
        return result

    monkeypatch.setattr(utils, "fast_safe_load", parse_then_change)
    monkeypatch.setattr(
        terminal_env_registry, "get_provider", lambda *_: calls.append("provider")
    )
    with pytest.raises(RecoveryRefused, match="unsupported_configuration"):
        prepare_static_chat_runtime(owner, session_id="protected-session")
    assert calls == []
