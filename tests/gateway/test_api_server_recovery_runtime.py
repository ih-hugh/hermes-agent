"""No-effect preparation of the one supported protected constructor route."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Callable
from threading import Event, Thread

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


def _selected_source_fixture(registry, monkeypatch, on_source: Callable[[float], None]):
    import sys
    from types import ModuleType
    from pydantic import BaseModel, ConfigDict, Field
    from tests.agent.test_recovery_runtime import _install_selected_plugin_fixture
    from tools import terminal_tool_config
    from hermes_cli import build_info

    manager, _ = _install_selected_plugin_fixture(registry, monkeypatch)
    module = ModuleType("byf_workspace")

    class BundleIdentity(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")
        source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
        provider_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    module.BundleIdentity = BundleIdentity
    monkeypatch.setitem(sys.modules, "byf_workspace", module)
    monkeypatch.setattr(manager._plugins["byf_workspace"], "module", module)

    def source(_self, *, deadline: float):
        on_source(deadline)
        return "1" * 40, BundleIdentity(
            source_sha256="a" * 64, provider_sha256="b" * 64
        )

    selected = type(
        "ByfWorkspaceProvider",
        (),
        {
            "__module__": module.__name__,
            "name": "byf_workspace",
            "read_recovery_source": source,
        },
    )()
    monkeypatch.setattr(
        terminal_tool_config, "_get_plugin_env_provider", lambda _: selected
    )
    monkeypatch.setattr(build_info, "get_code_identity", lambda: {"sha": "1" * 40})
    return manager


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


def test_source_only_readiness_uses_selected_native_type_without_issuing_preparation(
    tmp_path: Path, monkeypatch
) -> None:
    from agent import recovery_producers
    from tests.agent.test_recovery_runtime import _admitted
    from gateway.platforms.api_server_recovery_runtime import static_runtime_ready

    owner = _profile(tmp_path, monkeypatch)
    db, _, _, registry = _admitted(owner.home)
    calls: list[str] = []

    def on_source(deadline: float) -> None:
        assert deadline > 0
        calls.append("source")

    manager = _selected_source_fixture(registry, monkeypatch, on_source)
    monkeypatch.setattr(
        "gateway.platforms.api_server_recovery_runtime._issue_static_preparation",
        lambda *_: pytest.fail("source-only readiness issued constructor preparation"),
    )
    try:
        assert manager._discovered
        assert static_runtime_ready(owner, deadline=1_000_000_000.0)
        assert calls == ["source"]
        assert recovery_producers.current_registry() is None
        config = owner.home / "config.yaml"
        config.write_text(config.read_text().replace("128000", "64000"))
        assert static_runtime_ready(owner, deadline=1_000_000_000.0)
        config.write_text(config.read_text().replace("64000", "63999"))
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
        assert calls == ["source", "source"]
    finally:
        db.close()


def test_source_only_readiness_refuses_config_drift_after_source(
    tmp_path: Path, monkeypatch
) -> None:
    from tests.agent.test_recovery_runtime import _admitted
    from gateway.platforms.api_server_recovery_runtime import static_runtime_ready

    owner = _profile(tmp_path, monkeypatch)
    db, _, _, registry = _admitted(owner.home)

    def on_source(_deadline: float) -> None:
        config = owner.home / "config.yaml"
        config.write_text(config.read_text().replace("gpt-4.1", "gpt-4.2"))

    _selected_source_fixture(registry, monkeypatch, on_source)
    try:
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
    finally:
        db.close()


def test_source_only_readiness_refuses_wrong_source_type_revision_and_registration(
    tmp_path: Path, monkeypatch
) -> None:
    from types import SimpleNamespace
    from tests.agent.test_recovery_runtime import _admitted
    from tools import terminal_tool_config
    from gateway.platforms.api_server_recovery_runtime import static_runtime_ready

    owner = _profile(tmp_path, monkeypatch)
    db, _, _, registry = _admitted(owner.home)
    manager = _selected_source_fixture(registry, monkeypatch, lambda _: None)
    selected = terminal_tool_config._get_plugin_env_provider("byf_workspace")
    native = selected.read_recovery_source(deadline=1_000_000_000.0)[1]
    selected_type = type(selected)
    try:
        monkeypatch.setattr(
            selected_type, "read_recovery_source", lambda *_a, **_k: ("2" * 40, native)
        )
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
        monkeypatch.setattr(
            selected_type,
            "read_recovery_source",
            lambda *_a, **_k: ("1" * 40, SimpleNamespace(model_dump=native.model_dump)),
        )
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
        manager._plugins["byf_workspace"].enabled = False
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
    finally:
        db.close()


def test_source_only_readiness_holds_manager_lock_through_source_and_refuses_contention(
    tmp_path: Path, monkeypatch
) -> None:
    from tests.agent.test_recovery_runtime import _admitted
    from gateway.platforms.api_server_recovery_runtime import static_runtime_ready

    owner = _profile(tmp_path, monkeypatch)
    db, _, _, registry = _admitted(owner.home)
    competing_acquired: list[bool] = []

    def on_source(_deadline: float) -> None:
        lock = manager._discovery_lock

        def compete() -> None:
            acquired = lock.acquire(blocking=False)
            competing_acquired.append(acquired)
            if acquired:
                lock.release()

        worker = Thread(target=compete)
        worker.start()
        worker.join(2)
        assert not worker.is_alive()

    manager = _selected_source_fixture(registry, monkeypatch, on_source)
    entered = Event()
    release = Event()

    def hold_lock() -> None:
        with manager._discovery_lock:
            entered.set()
            assert release.wait(2)

    holder = Thread(target=hold_lock)
    try:
        assert static_runtime_ready(owner, deadline=1_000_000_000.0)
        assert competing_acquired == [False]
        holder.start()
        assert entered.wait(2)
        assert not static_runtime_ready(owner, deadline=1_000_000_000.0)
        assert competing_acquired == [False]
    finally:
        release.set()
        if holder.ident is not None:
            holder.join(2)
        db.close()
