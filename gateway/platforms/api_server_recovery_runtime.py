"""No-effect preparation for the initial protected chat-completions route.

This object is private constructor input, never admission or source authority.
The authenticated owner context is produced by the HTTP layer; the durable
RecoveryStore and selected workspace provider still decide whether work exists.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from agent.recovery_producers import (
    FrozenProtectedRuntime,
    _issue_static_preparation,
    loaded_selected_provider_supported,
    read_bounded_protected_config,
)
from hermes_state_recovery import RecoveryRefused

if TYPE_CHECKING:
    from gateway.platforms.api_server_recovery import RecoveryOwnerContext
    from hermes_cli.plugins import PluginManager


_OPENAI_BASE = "https://api.openai.com/v1"
_MODEL_FIELDS = frozenset({"provider", "api_mode", "default", "context_length"})
_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class _SourceIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class _StaticInputs:
    profile: str
    home: Path
    scope_digest: str = field(repr=False)
    model: str
    key: str = field(repr=False)
    config_json: bytes = field(repr=False)
    config_sha256: str
    manager: PluginManager = field(repr=False)
    provider: object = field(repr=False)
    tool_generation: int
    terminal_generation: tuple[int, int]


def _refuse() -> None:
    raise RecoveryRefused("unsupported_configuration")


def _mapping(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _refuse()
    return value


def prepare_static_chat_runtime(
    owner: RecoveryOwnerContext, *, session_id: str
) -> FrozenProtectedRuntime:
    """Validate exact loaded local inputs before any protected constructor effect."""
    if type(session_id) is not str or not 1 <= len(session_id) <= 128:
        _refuse()
    inputs = _inspect_static_chat_runtime(owner)
    return _issue_static_preparation(
        FrozenProtectedRuntime(
            inputs.profile,
            inputs.home,
            inputs.scope_digest,
            session_id,
            inputs.model,
            "openai-api",
            "chat_completions",
            _OPENAI_BASE,
            inputs.key,
            inputs.config_json,
            inputs.config_sha256,
            inputs.manager,
            inputs.provider,
            inputs.tool_generation,
            inputs.terminal_generation,
        )
    )


def _inspect_static_chat_runtime(owner: RecoveryOwnerContext) -> _StaticInputs:
    """Inspect configured/loaded inputs without minting a constructor capability."""
    # Startup warmup may time out. Never perform its lazy import graph on the
    # protected admission/readiness path after taking a registry snapshot.
    run_module = sys.modules.get("run_agent")
    tools_module = sys.modules.get("model_tools")
    if (
        run_module is None
        or getattr(getattr(run_module, "__spec__", None), "_initializing", True)
        or not isinstance(getattr(run_module, "AIAgent", None), type)
        or tools_module is None
        or getattr(getattr(tools_module, "__spec__", None), "_initializing", True)
        or not callable(getattr(tools_module, "get_tool_definitions", None))
    ):
        _refuse()
    from agent.model_metadata import MINIMUM_CONTEXT_LENGTH
    from agent.secret_scope import get_secret_str
    from agent.terminal_env_registry import registry_generation
    from hermes_cli.auth import has_usable_secret
    from hermes_cli.config import get_config_path
    from hermes_cli.plugins import get_plugin_manager
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home
    from tools.registry import registry as tool_registry
    from tools.terminal_tool import TERMINAL_SCHEMA, _handle_terminal
    from tools.terminal_tool_config import _get_plugin_env_provider
    from utils import fast_safe_load

    if (
        type(owner.profile) is not str
        or not owner.profile
        or type(owner.scope_digest) is not str
        or len(owner.scope_digest) != 64
        or not isinstance(owner.home, Path)
        or not owner.home.is_absolute()
        or get_active_profile_name() != owner.profile
        or get_hermes_home().resolve() != owner.home.resolve()
    ):
        _refuse()
    try:
        config_path = get_config_path()
        if config_path.resolve() != owner.home.resolve() / "config.yaml":
            _refuse()
        raw_bytes = read_bounded_protected_config(config_path)
        raw = _mapping(fast_safe_load(io.StringIO(raw_bytes.decode("utf-8"))))
        if read_bounded_protected_config(config_path) != raw_bytes:
            _refuse()

        platforms = _mapping(raw.get("platforms"))
        api = _mapping(platforms.get("api_server"))
        recovery = _mapping(api.get("recovery"))
        if recovery.get("enabled") is not True:
            _refuse()
        platform_toolsets = _mapping(raw.get("platform_toolsets"))
        if platform_toolsets.get("api_server") != ["terminal_only", "no_mcp"]:
            _refuse()
        tools = _mapping(raw.get("tools"))
        tool_search = _mapping(tools.get("tool_search"))
        if (
            tool_search.get("enabled") != "off"
            or set(tools) != {"tool_search"}
            or set(tool_search) != {"enabled"}
        ):
            _refuse()
        terminal = _mapping(raw.get("terminal"))
        context = _mapping(raw.get("context"))
        if terminal.get("backend") != "byf_workspace" or context != {
            "engine": "compressor"
        }:
            _refuse()
        model_cfg = _mapping(raw.get("model"))
        model = model_cfg.get("default")
        length = model_cfg.get("context_length")
        if (
            set(model_cfg) - _MODEL_FIELDS
            or model_cfg.get("provider") != "openai-api"
            or model_cfg.get("api_mode") != "chat_completions"
            or type(model) is not str
            or not 1 <= len(model) <= 256
            or model != model.strip()
            or type(length) is not int
            or length < MINIMUM_CONTEXT_LENGTH
            or raw.get("custom_providers") not in (None, [])
            or raw.get("fallback_model") not in (None, [])
            or any(
                raw.get(name) not in (None, {})
                for name in (
                    "memory",
                    "auxiliary",
                    "compression",
                    "agent",
                    "prompt_caching",
                )
            )
        ):
            _refuse()
        key = get_secret_str("OPENAI_API_KEY")
        if (
            not has_usable_secret(key)
            or len(key) > 4096
            or get_secret_str("OPENAI_BASE_URL")
            or not isinstance(key, str)
        ):
            _refuse()

        manager = get_plugin_manager()
        lock = manager._discovery_lock
        if not lock.acquire(blocking=False):
            _refuse()
        try:
            provider = _get_plugin_env_provider("byf_workspace")
            entry = tool_registry.get_entry("terminal")
            if (
                provider is None
                or manager.home_path.resolve() != owner.home.resolve()
                or not loaded_selected_provider_supported(manager, provider)
                or entry is None
                or entry.toolset != "terminal"
                or entry.schema is not TERMINAL_SCHEMA
                or entry.handler is not _handle_terminal
                or entry.dynamic_schema_overrides is not None
                or entry.is_async
            ):
                _refuse()
            tool_generation = tool_registry._generation
            terminal_generation = registry_generation()
        finally:
            lock.release()

        # Only constructor-relevant, non-secret scalars cross this private seam.
        safe_config = {
            "model": {
                "default": model,
                "provider": "openai-api",
                "api_mode": "chat_completions",
                "context_length": length,
            },
            "context": {"engine": "compressor"},
            "tools": {"tool_search": {"enabled": "off"}},
            "agent": {"environment_probe": False},
        }
        config_json = json.dumps(
            safe_config,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return _StaticInputs(
            owner.profile,
            owner.home.resolve(),
            owner.scope_digest,
            model,
            key,
            config_json,
            hashlib.sha256(raw_bytes).hexdigest(),
            manager,
            provider,
            tool_generation,
            terminal_generation,
        )
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("unsupported_configuration") from exc


def static_runtime_ready(owner: RecoveryOwnerContext, *, deadline: float) -> bool:
    """Observe exact loaded source eligibility; never issue work authority."""
    from hermes_cli.build_info import get_code_identity

    if (
        type(deadline) is not float
        or not math.isfinite(deadline)
        or deadline <= time.monotonic()
    ):
        return False
    try:
        before = _inspect_static_chat_runtime(owner)
        lock = before.manager._discovery_lock
        if not lock.acquire(blocking=False):
            return False
        try:
            # PluginManager uses an RLock; the shared inspection reacquires it
            # on this same worker without opening a reload window.
            locked = _inspect_static_chat_runtime(owner)
            if not _same_static_inputs(before, locked):
                return False
            provider = locked.provider
            selected_module = sys.modules.get(type(provider).__module__)
            native_type = getattr(selected_module, "BundleIdentity", None)
            inspect_source = getattr(provider, "read_recovery_source", None)
            if (
                type(provider).__name__ != "ByfWorkspaceProvider"
                or type(provider).__module__.split(".")[-1] != "byf_workspace"
                or selected_module is None
                or not isinstance(native_type, type)
                or not callable(inspect_source)
            ):
                return False
            raw = inspect_source(deadline=deadline)
            if type(raw) is not tuple or len(raw) != 2:
                return False
            revision, native = raw
            candidate = get_code_identity().get("sha")
            if (
                type(revision) is not str
                or _REVISION.fullmatch(revision) is None
                or revision != candidate
                or type(native) is not native_type
            ):
                return False
            source = _SourceIdentity.model_validate(native.model_dump(mode="json"))
            if native.model_dump(mode="json") != source.model_dump():
                return False
            after = _inspect_static_chat_runtime(owner)
            return time.monotonic() < deadline and _same_static_inputs(locked, after)
        finally:
            lock.release()
    except Exception:
        return False


def _same_static_inputs(left: _StaticInputs, right: _StaticInputs) -> bool:
    return (
        left.profile == right.profile
        and left.home == right.home
        and left.scope_digest == right.scope_digest
        and left.model == right.model
        and left.key == right.key
        and left.config_json == right.config_json
        and left.config_sha256 == right.config_sha256
        and left.manager is right.manager
        and left.provider is right.provider
        and left.tool_generation == right.tool_generation
        and left.terminal_generation == right.terminal_generation
    )
