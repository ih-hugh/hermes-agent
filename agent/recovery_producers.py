"""Process-owned producer leases and durable physical provider-send inventory.

The ledger is active only for an explicitly admitted protected run. Context variables
carry its identity across known threads; the database, not those variables, is the
authority for closure and send accounting.
"""

from __future__ import annotations

import threading
import uuid
import weakref
import sys
import math
import hashlib
import json
import os
import stat
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterator, Literal, TypeVar

from agent.recovery_context import ProducerPermit, _register_usage_completion
from hermes_state_recovery import RecoveryRefused

if TYPE_CHECKING:
    from agent.recovery_context import UsageCompletion
    from hermes_state_recovery import RecoveryScope, RecoveryStore
    from hermes_cli.plugins import PluginManager


T = TypeVar("T")
ProducerKind = Literal["executor", "tool", "sdk", "callback", "usage_write"]
SendOutcomeKind = Literal["accounted", "no_charge_proved", "unknown"]
_KINDS = frozenset({"executor", "tool", "sdk", "callback", "usage_write"})
_ACTIVE_REGISTRY: ContextVar[ProducerRegistry | None] = ContextVar(
    "recovery_producer_registry", default=None
)
_ACTIVE_LEASE: ContextVar[ProducerLease | None] = ContextVar(
    "recovery_producer_lease", default=None
)
_CONSTRUCTOR_PREPARATION: ContextVar[FrozenProtectedRuntime | None] = ContextVar(
    "recovery_constructor_preparation", default=None
)
_SEND_ISSUER = object()
_LEASE_ISSUER = object()
_SEND_LOCK = threading.Lock()
_SEND_MAP: weakref.WeakKeyDictionary[SendPermit, tuple[ProducerRegistry, str, str]] = (
    weakref.WeakKeyDictionary()
)
_PREPARATION_LOCK = threading.Lock()
_ISSUED_PREPARATIONS: weakref.WeakValueDictionary[int, FrozenProtectedRuntime] = (
    weakref.WeakValueDictionary()
)
_MAX_PROTECTED_CONFIG_BYTES = 1_048_576


def read_bounded_protected_config(path: Path) -> bytes:
    """Read one exact regular config image without unbounded allocation."""
    try:
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROTECTED_CONFIG_BYTES:
                raise RecoveryRefused("unsupported_configuration")
            raw = stream.read(_MAX_PROTECTED_CONFIG_BYTES + 1)
    except RecoveryRefused:
        raise
    except OSError as exc:
        raise RecoveryRefused("unsupported_configuration") from exc
    if len(raw) > _MAX_PROTECTED_CONFIG_BYTES:
        raise RecoveryRefused("unsupported_configuration")
    return raw


def current_registry() -> ProducerRegistry | None:
    return _ACTIVE_REGISTRY.get()


def current_lease() -> ProducerLease | None:
    return _ACTIVE_LEASE.get()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class FrozenProtectedRuntime:
    """Private same-process constructor input; never a recovery authority."""

    profile: str
    home: Path
    scope_digest: str = field(repr=False)
    session_id: str
    model: str
    provider: str
    api_mode: str
    base_url: str
    api_key: str = field(repr=False, compare=False)
    config_json: bytes = field(repr=False, compare=False)
    config_sha256: str = field(repr=False)
    manager: PluginManager = field(repr=False, compare=False)
    selected_provider: object = field(repr=False, compare=False)
    tool_generation: int
    terminal_registry_generation: tuple[int, int]

    def agent_config(self) -> dict[str, object]:
        """Give constructor helpers a fresh copy of the validated safe subset."""
        return json.loads(self.config_json)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("protected runtime preparation cannot be serialized")


def current_constructor_preparation() -> FrozenProtectedRuntime | None:
    return _CONSTRUCTOR_PREPARATION.get()


def _issue_static_preparation(prepared: FrozenProtectedRuntime) -> FrozenProtectedRuntime:
    """Retain only this exact same-process preparation object, not copied fields."""
    if type(prepared) is not FrozenProtectedRuntime:
        raise RecoveryRefused("unsupported_configuration")
    with _PREPARATION_LOCK:
        _ISSUED_PREPARATIONS[id(prepared)] = prepared
    return prepared


def _require_preparation_current(prepared: FrozenProtectedRuntime) -> ProducerRegistry:
    """Check exact selected profile and loaded identities without callback/discovery."""
    from agent.secret_scope import get_secret_str
    from agent.terminal_env_registry import registry_generation
    from hermes_cli.plugins import get_plugin_manager
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home
    from hermes_cli.config import get_config_path
    from tools.registry import registry as tool_registry
    from tools.terminal_tool_config import _get_plugin_env_provider

    with _PREPARATION_LOCK:
        if _ISSUED_PREPARATIONS.get(id(prepared)) is not prepared:
            raise RecoveryRefused("unsupported_configuration")
    try:
        registry = current_registry()
        if (registry is None
                or registry.scope.profile != prepared.profile
                or registry.scope.scope_digest != prepared.scope_digest
                or registry.scope.session_id != prepared.session_id
                or get_active_profile_name() != prepared.profile
                or get_hermes_home().resolve() != prepared.home.resolve()
                or get_plugin_manager() is not prepared.manager
                or not getattr(prepared.manager, "_discovered", False)
                or tool_registry._generation != prepared.tool_generation
                or registry_generation() != prepared.terminal_registry_generation
                or _get_plugin_env_provider("byf_workspace") is not prepared.selected_provider
                or not loaded_selected_provider_supported(
                    prepared.manager, prepared.selected_provider
                )
                or get_secret_str("OPENAI_API_KEY") != prepared.api_key):
            raise RecoveryRefused("unsupported_configuration")
        raw = read_bounded_protected_config(get_config_path())
        if hashlib.sha256(raw).hexdigest() != prepared.config_sha256:
            raise RecoveryRefused("unsupported_configuration")
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("unsupported_configuration") from exc
    return registry


@contextmanager
def bind_protected_constructor(prepared: FrozenProtectedRuntime) -> Iterator[None]:
    """Pin the discovered manager for one bounded AIAgent construction only."""
    if type(prepared) is not FrozenProtectedRuntime:
        raise RecoveryRefused("unsupported_configuration")
    lock = getattr(prepared.manager, "_discovery_lock", None)
    if lock is None or not lock.acquire(blocking=False):
        raise RecoveryRefused("unsupported_configuration")
    token = None
    try:
        _require_preparation_current(prepared)
        token = _CONSTRUCTOR_PREPARATION.set(prepared)
        yield
        _require_preparation_current(prepared)
    finally:
        if token is not None:
            _CONSTRUCTOR_PREPARATION.reset(token)
        lock.release()


def require_protected_constructor(
    session_id: str, *, model: str, provider: str | None, api_mode: str | None,
    base_url: str | None, api_key: str | None, enabled_toolsets: list[str] | None,
    disabled_toolsets: list[str] | None, fallback_model: object, credential_pool: object,
    request_overrides: object, skip_memory: bool, skip_background_review: bool,
    skip_context_files: bool, platform: str | None,
) -> FrozenProtectedRuntime | None:
    """Refuse unprepared protected construction before session/client/tool effects."""
    if current_registry() is None:
        return None
    prepared = current_constructor_preparation()
    if (prepared is None
            or session_id != prepared.session_id
            or model != prepared.model
            or provider != prepared.provider
            or api_mode != prepared.api_mode
            or base_url != prepared.base_url
            or api_key != prepared.api_key
            or enabled_toolsets != ["terminal_only"]
            or disabled_toolsets not in (None, [])
            or fallback_model is not None
            or credential_pool is not None
            or request_overrides not in (None, {})
            or not skip_memory or not skip_background_review or not skip_context_files
            or platform != "api_server"):
        raise RecoveryRefused("unsupported_configuration")
    _require_preparation_current(prepared)
    return prepared


def refuse_untracked_work() -> None:
    """Reject an unsupported protected dispatch before its first side effect."""
    registry = current_registry()
    if registry is not None:
        registry.mark_unsupported("unsupported_configuration")
        raise RecoveryRefused("unsupported_configuration")


def require_unmanaged_dispatch() -> None:
    """Only the direct Hermes call chain has a complete producer inventory."""
    if current_registry() is None:
        return
    from agent import relay_runtime
    from hermes_cli.plugins import get_plugin_manager

    runtime = relay_runtime.get_runtime(create=False)
    if ((runtime is not None and runtime.managed_execution_enabled())
            or any(get_plugin_manager()._middleware.values())):
        refuse_untracked_work()


def loaded_selected_provider_supported(manager: PluginManager, provider: object) -> bool:
    """Inspect only settled registration slots; invoke no selected plugin method."""
    from hermes_cli.plugins_manifest import manifest_key
    from agent.tool_diagnostic_transport import (
        _BUNDLED_PLUGIN_ROOT,
        _UNOBSERVED_CALLBACK_REGISTRIES,
        _only_stock_gateway_injector,
        _only_stock_raft_hooks,
    )

    hooks = {kind: callbacks for kind, callbacks in manager._hooks.items() if callbacks}
    if (not manager._discovered
            or any(manager._middleware.values())
            or (hooks and not _only_stock_raft_hooks(hooks))
            or manager._aux_tasks
            or manager._context_engine is not None
            or manager._subscriptions
            or manager._persistent_carryover
            or not _only_stock_gateway_injector(manager._gateway_message_injector)
            or any(getattr(manager, name, None) for name in _UNOBSERVED_CALLBACK_REGISTRIES)):
        return False
    selected_plugin_seen = False
    for loaded in manager._plugins.values():
        if not loaded.enabled:
            continue
        manifest = loaded.manifest
        source = getattr(manifest, "path", None)
        bundled = (getattr(manifest, "source", None) == "bundled"
                   and isinstance(source, str)
                   and Path(source).resolve().is_relative_to(_BUNDLED_PLUGIN_ROOT))
        if bundled:
            continue
        if (selected_plugin_seen
                or manifest.name != "byf_workspace"
                or loaded.module is not sys.modules.get(type(provider).__module__)):
            return False
        owned = [r for r in manager._ownership_ledger.get(manifest_key(manifest), ()) if r.active]
        if len(owned) != 1 or (owned[0].kind, owned[0].key) != (
            "terminal_environment_provider", "byf_workspace"
        ):
            return False
        selected_plugin_seen = True
    return selected_plugin_seen


def _selected_provider_and_callbacks_supported(registry: ProducerRegistry) -> bool:
    """Recheck the captured selected plugin after ordinary config resolution."""
    from hermes_cli.plugins import get_plugin_manager
    from hermes_state_recovery_provider import SelectedProviderCapture

    capture = getattr(registry, "provider_capture", None)
    if (type(capture) is not SelectedProviderCapture
            or capture.admission.session_id != registry.scope.session_id):
        return False
    provider = capture.require_selected()
    return loaded_selected_provider_supported(get_plugin_manager(), provider)


def _exact_terminal_schema(agent: object) -> bool:
    from tools.registry import registry as tool_registry
    from tools.terminal_tool import TERMINAL_SCHEMA, _handle_terminal

    entry = tool_registry.get_entry("terminal")
    tools = getattr(agent, "tools", None)
    names = getattr(agent, "valid_tool_names", None)
    if (entry is None
            or entry.toolset != "terminal"
            or entry.schema is not TERMINAL_SCHEMA
            or entry.handler is not _handle_terminal
            or entry.dynamic_schema_overrides is not None
            or entry.is_async
            or type(tools) is not list
            or len(tools) != 1
            or type(names) is not set
            or names != {"terminal"}
            or getattr(agent, "_tool_snapshot_generation", None) != tool_registry._generation):
        return False
    schema = tools[0]
    return (type(schema) is dict
            and schema == {"type": "function", "function": TERMINAL_SCHEMA})


def require_supported_chat_agent(agent: object, *, moa_config: object = None) -> None:
    """Refuse a protected turn before an uninventoryable provider path can run."""
    registry = current_registry()
    if registry is None:
        return
    toolsets = getattr(agent, "enabled_toolsets", None)
    try:
        from agent.context_compressor import ContextCompressor
        supported = (
            getattr(agent, "api_mode", None) == "chat_completions"
            and getattr(agent, "provider", None) != "moa"
            and moa_config is None
            and not bool(getattr(agent, "is_subagent", False))
            and not bool(getattr(agent, "_fallback_index", 0))
            and not bool(getattr(agent, "_fallback_activated", False))
            and not bool(getattr(agent, "_fallback_chain", None))
            and isinstance(toolsets, (list, tuple, set, frozenset))
            and len(toolsets) == 1
            and set(toolsets) == {"terminal_only"}
            and type(getattr(agent, "context_compressor", None)) is ContextCompressor
            and getattr(agent, "_memory_manager", None) is None
            and getattr(agent, "_memory_store", None) is None
            and bool(getattr(agent, "skip_background_review", False))
            and _exact_terminal_schema(agent)
            and _selected_provider_and_callbacks_supported(registry)
        )
    except Exception:
        supported = False
    if not supported:
        registry.mark_unsupported("unsupported_configuration")
        raise RecoveryRefused("unsupported_configuration")


def require_effective_chat_request(
    agent: object, kwargs: object, *, expected_stream: bool
) -> None:
    """Validate the final kwargs against this physical SDK dispatch mode."""
    if current_registry() is None:
        return
    require_supported_chat_agent(agent)
    allowed = frozenset({
        "model", "messages", "tools", "timeout", "temperature", "max_tokens",
        "max_completion_tokens", "reasoning_effort", "prompt_cache_key", "stream",
        "stream_options",
    })
    def valid_timeout(value: object) -> bool:
        import httpx

        if type(value) in (int, float):
            return math.isfinite(value) and value > 0
        if type(value) is httpx.Timeout:
            parts = (value.connect, value.read, value.write, value.pool)
            return all(type(part) in (int, float) and math.isfinite(part) and part > 0
                       for part in parts)
        return False

    if (type(kwargs) is not dict
            or not set(kwargs).issubset(allowed)
            or type(kwargs.get("model")) is not str
            or kwargs["model"] != getattr(agent, "model", None)
            or type(kwargs.get("messages")) is not list
            or type(kwargs.get("tools")) is not list
            or kwargs.get("tools") != agent.tools
            or ("timeout" in kwargs and not valid_timeout(kwargs["timeout"]))
            or (expected_stream and kwargs.get("stream") is not True)
            or (expected_stream and kwargs.get("stream_options") != {"include_usage": True})
            or (expected_stream and bool(getattr(agent, "_stream_options_unsupported", False)))
            or (not expected_stream and "stream" in kwargs and kwargs["stream"] is not False)
            or (not expected_stream and "stream_options" in kwargs)):
        refuse_untracked_work()


def begin_chat_send(client: object) -> SendPermit | None:
    """Inventory one physical OpenAI SDK invocation, refusing hidden retries."""
    registry = current_registry()
    if registry is None:
        return None
    from openai import OpenAI
    from openai._base_client import SyncHttpxClientWrapper
    from httpx import HTTPTransport

    http_client = getattr(client, "_client", None)
    if (type(client) is not OpenAI
            or type(getattr(client, "max_retries", None)) is not int
            or client.max_retries != 0
            or type(http_client) is not SyncHttpxClientWrapper
            or type(getattr(http_client, "_transport", None)) is not HTTPTransport
            or bool(getattr(http_client, "_mounts", None))):
        registry.mark_unsupported("unsupported_configuration")
        raise RecoveryRefused("unsupported_configuration")
    return registry.sends.begin(registry.permit, f"send_{uuid.uuid4().hex}")


def finish_unknown_if_active(send: SendPermit | None, reason: str) -> None:
    """Retain uncertainty for a started send with no committed usage acknowledgement."""
    if send is None:
        return
    with _SEND_LOCK:
        record = _SEND_MAP.get(send)
    if record is not None:
        send.finish(SendOutcome(kind="unknown", attempt_id=send.attempt_id, reason=reason))


@dataclass(frozen=True, slots=True)
class SendOutcome:
    kind: SendOutcomeKind
    attempt_id: str
    acknowledged_delta_ids: tuple[str, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        if (
            self.kind not in {"accounted", "no_charge_proved", "unknown"}
            or type(self.attempt_id) is not str
            or not self.attempt_id
            or type(self.acknowledged_delta_ids) is not tuple
            or any(
                type(item) is not str or not item
                for item in self.acknowledged_delta_ids
            )
        ):
            raise ValueError("invalid send outcome")
        if self.kind == "accounted":
            if not self.acknowledged_delta_ids or self.reason is not None:
                raise ValueError("accounted requires acknowledged delta IDs")
        elif (
            self.acknowledged_delta_ids
            or type(self.reason) is not str
            or not self.reason
            or len(self.reason) > 80
        ):
            raise ValueError("invalid send outcome reason")


class SendPermit:
    """Opaque one-use authority for one already admitted SDK invocation."""

    __slots__ = ("__weakref__", "_attempt_id", "_delta_id", "_completion", "_used")

    def __init__(
        self,
        issuer: object,
        attempt_id: str,
        delta_id: str,
        completion: UsageCompletion,
    ):
        if issuer is not _SEND_ISSUER:
            raise TypeError("send permits are issued internally")
        self._attempt_id, self._delta_id, self._completion, self._used = (
            attempt_id,
            delta_id,
            completion,
            False,
        )

    def __reduce_ex__(self, protocol: int):
        raise TypeError("send permits cannot be copied or serialized")

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    @property
    def delta_id(self) -> str:
        return self._delta_id

    @property
    def completion(self) -> UsageCompletion:
        return self._completion

    def invoke(self, fn: Callable[[], T]) -> T:
        """Consume before entering the SDK; a close after begin cannot revoke it."""
        with _SEND_LOCK:
            record = _SEND_MAP.get(self)
            if record is None or self._used:
                raise RecoveryRefused("send_attempt_consumed")
            registry, attempt_id, _ = record
            registry.store.invoke_send(
                registry.scope, registry.run_id, registry.permit, attempt_id
            )
            self._used = True
        try:
            return fn()
        except BaseException:
            registry.sends.finish(
                self,
                SendOutcome(
                    kind="unknown", attempt_id=attempt_id, reason="sdk_exception"
                ),
            )
            raise

    def finish(self, outcome: SendOutcome) -> None:
        with _SEND_LOCK:
            record = _SEND_MAP.get(self)
        if record is None:
            raise RecoveryRefused("invalid_send_permit")
        record[0].sends.finish(self, outcome)


class SendLedger:
    def __init__(self, registry: ProducerRegistry):
        self.registry = registry

    def begin(self, permit: ProducerPermit, attempt_id: str) -> SendPermit:
        registry = self.registry
        lease = current_lease()
        if (
            permit is not registry.permit
            or lease is None
            or lease.registry is not registry
            or lease.kind != "sdk"
        ):
            raise RecoveryRefused("invalid_send_producer")
        if not attempt_id or len(attempt_id) > 128:
            raise RecoveryRefused("invalid_send_attempt")
        delta_id = f"{attempt_id}:usage"
        if len(delta_id) > 160:
            raise RecoveryRefused("invalid_send_attempt")
        registry.store.begin_send(
            registry.scope,
            registry.run_id,
            permit,
            lease.producer_id,
            attempt_id,
            delta_id,
        )
        completion = _register_usage_completion(
            registry.store,
            registry.scope,
            registry.run_id,
            registry.generation,
            lease.producer_id,
            attempt_id,
            delta_id,
        )
        send = SendPermit(_SEND_ISSUER, attempt_id, delta_id, completion)
        with _SEND_LOCK:
            _SEND_MAP[send] = (registry, attempt_id, delta_id)
        return send

    def finish(self, send: SendPermit, outcome: SendOutcome) -> None:
        if type(send) is not SendPermit or type(outcome) is not SendOutcome:
            raise RecoveryRefused("invalid_send_permit")
        with _SEND_LOCK:
            record = _SEND_MAP.get(send)
            if (
                record is None
                or record[0] is not self.registry
                or outcome.attempt_id != record[1]
            ):
                raise RecoveryRefused("invalid_send_permit")
            if outcome.kind == "accounted" and outcome.acknowledged_delta_ids != (
                record[2],
            ):
                raise RecoveryRefused("usage_ack_required")
            self.registry.store.finish_send(
                self.registry.scope,
                self.registry.run_id,
                self.registry.permit,
                record[1],
                outcome.kind,
                outcome.reason,
            )
            _SEND_MAP.pop(send, None)


class ProducerLease:
    __slots__ = ("registry", "producer_id", "kind", "_lock", "_state")

    def __init__(
        self, issuer: object, registry: ProducerRegistry, producer_id: str, kind: ProducerKind
    ):
        if issuer is not _LEASE_ISSUER:
            raise TypeError("producer leases are issued internally")
        self.registry, self.producer_id, self.kind = registry, producer_id, kind
        self._lock = threading.Lock()
        self._state = "queued"

    def __reduce_ex__(self, protocol: int):
        raise TypeError("producer leases cannot be copied or serialized")

    def run(self, fn: Callable[[], T]) -> T:
        with self._lock:
            if self._state != "queued":
                raise RecoveryRefused("producer_already_started")
            self.registry.store.start_registered_producer(
                self.registry.scope,
                self.registry.run_id,
                self.registry.permit,
                self.producer_id,
            )
            self._state = "running"
        registry_token = _ACTIVE_REGISTRY.set(self.registry)
        lease_token = _ACTIVE_LEASE.set(self)
        try:
            return fn()
        finally:
            _ACTIVE_LEASE.reset(lease_token)
            _ACTIVE_REGISTRY.reset(registry_token)
            self.registry.store.close_registered_producer(
                self.registry.scope,
                self.registry.run_id,
                self.registry.permit,
                self.producer_id,
            )
            with self._lock:
                self._state = "closed"
            self.registry._notify_lease_settled()

    def cancel_before_start(self) -> None:
        """Caller may use this only after proving submission never began (e.g. Future.cancel true)."""
        with self._lock:
            if self._state != "queued":
                raise RecoveryRefused("producer_already_started")
            self.registry.store.cancel_registered_producer(
                self.registry.scope,
                self.registry.run_id,
                self.registry.permit,
                self.producer_id,
            )
            self._state = "cancelled"
        self.registry._notify_lease_settled()


class ProducerRegistry:
    def __init__(
        self,
        store: RecoveryStore,
        scope: RecoveryScope,
        run_id: str,
        generation: int,
        permit: ProducerPermit,
    ):
        from agent.recovery_context import validate_producer_permit

        if not validate_producer_permit(permit, store, scope, run_id, generation):
            raise RecoveryRefused("invalid_producer_permit")
        self.store, self.scope, self.run_id, self.generation, self.permit = (
            store,
            scope,
            run_id,
            generation,
            permit,
        )
        self.sends = SendLedger(self)
        self._lock = threading.Lock()
        self._settled = threading.Condition(self._lock)
        self._close_requested = False
        self._leases: dict[str, ProducerLease] = {}
        self._response_sends: dict[int, tuple[object, SendPermit]] = {}

    def enter(self, parent: ProducerPermit | ProducerLease, kind: ProducerKind) -> ProducerLease:
        if kind not in _KINDS:
            raise RecoveryRefused("invalid_producer_permit")
        with self._lock:
            parent_id = None
            if parent is self.permit:
                if self._close_requested:
                    raise RecoveryRefused("producer_closed")
            elif (type(parent) is ProducerLease and parent.registry is self
                  and self._leases.get(parent.producer_id) is parent and kind == "callback"):
                with parent._lock:
                    if parent._state != "running":
                        raise RecoveryRefused("invalid_callback_parent")
                parent_id = parent.producer_id
            else:
                raise RecoveryRefused("invalid_callback_parent")
            producer_id = f"producer_{uuid.uuid4().hex}"
            self.store.register_producer(
                self.scope, self.run_id, self.permit, producer_id, kind, parent_id
            )
            lease = ProducerLease(_LEASE_ISSUER, self, producer_id, kind)
            self._leases[producer_id] = lease
            return lease

    def _notify_lease_settled(self) -> None:
        with self._settled:
            self._settled.notify_all()

    def wait_until_quiescent(self, *, excluding: ProducerLease) -> None:
        """Join actual child completion before an ordered status-write barrier."""
        if excluding.registry is not self:
            raise RecoveryRefused("invalid_callback_parent")
        with self._settled:
            self._settled.wait_for(lambda: all(
                lease is excluding or lease._state in {"closed", "cancelled"}
                for lease in self._leases.values()))

    def request_close(self) -> None:
        with self._lock:
            if self._close_requested:
                return
            self.store.request_producer_close(self.scope, self.run_id, self.permit)
            self._close_requested = True

    def mark_unsupported(self, reason: str = "unsupported_configuration") -> None:
        self.store.note_producer_incomplete(
            self.scope, self.run_id, self.permit, reason
        )

    def bind_response_send(self, response: object, send: SendPermit) -> None:
        """Attach only an existing exact send to a response crossing an SDK thread."""
        with _SEND_LOCK:
            record = _SEND_MAP.get(send)
        if record is None or record[0] is not self:
            raise RecoveryRefused("invalid_send_permit")
        with self._lock:
            key = id(response)
            prior = self._response_sends.get(key)
            if prior is not None:
                if prior[0] is response and prior[1] is send:
                    return
                raise RecoveryRefused("response_send_collision")
            self._response_sends[key] = (response, send)

    def claim_response_send(self, response: object) -> SendPermit | None:
        """Consume the private association; Task 3 receives the original one-use completion."""
        with self._lock:
            pair = self._response_sends.pop(id(response), None)
        if pair is None:
            return None
        if pair[0] is not response:
            raise RecoveryRefused("response_send_collision")
        return pair[1]


@contextmanager
def bind_registry(registry: ProducerRegistry) -> Iterator[None]:
    token = _ACTIVE_REGISTRY.set(registry)
    try:
        yield
    finally:
        _ACTIVE_REGISTRY.reset(token)
