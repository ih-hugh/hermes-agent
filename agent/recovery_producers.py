"""Process-owned producer leases and durable physical provider-send inventory.

The ledger is active only for an explicitly admitted protected run. Context variables
carry its identity across known threads; the database, not those variables, is the
authority for closure and send accounting.
"""

from __future__ import annotations

import threading
import uuid
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterator, Literal, TypeVar

from agent.recovery_context import ProducerPermit, _register_usage_completion
from hermes_state_recovery import RecoveryRefused

if TYPE_CHECKING:
    from agent.recovery_context import UsageCompletion
    from hermes_state_recovery import RecoveryScope, RecoveryStore


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
_SEND_ISSUER = object()
_LEASE_ISSUER = object()
_SEND_LOCK = threading.Lock()
_SEND_MAP: weakref.WeakKeyDictionary[SendPermit, tuple[ProducerRegistry, str, str]] = (
    weakref.WeakKeyDictionary()
)


def current_registry() -> ProducerRegistry | None:
    return _ACTIVE_REGISTRY.get()


def current_lease() -> ProducerLease | None:
    return _ACTIVE_LEASE.get()


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
    from hermes_cli.middleware import (
        LLM_EXECUTION_MIDDLEWARE,
        LLM_REQUEST_MIDDLEWARE,
        TOOL_EXECUTION_MIDDLEWARE,
        TOOL_REQUEST_MIDDLEWARE,
    )
    from hermes_cli.plugins import has_middleware

    runtime = relay_runtime.get_runtime(create=False)
    if ((runtime is not None and runtime.managed_execution_enabled())
            or any(has_middleware(kind) for kind in (
                LLM_REQUEST_MIDDLEWARE, LLM_EXECUTION_MIDDLEWARE,
                TOOL_REQUEST_MIDDLEWARE, TOOL_EXECUTION_MIDDLEWARE))):
        refuse_untracked_work()


def require_supported_chat_agent(agent: object) -> None:
    """Refuse a protected turn before an uninventoryable provider path can run."""
    registry = current_registry()
    if registry is None:
        return
    toolsets = getattr(agent, "enabled_toolsets", None)
    if (getattr(agent, "api_mode", None) != "chat_completions"
            or getattr(agent, "provider", None) == "moa"
            or bool(getattr(agent, "is_subagent", False))
            or bool(getattr(agent, "_fallback_index", 0))
            or not isinstance(toolsets, (list, tuple, set, frozenset))
            or not set(toolsets) <= {"terminal"}):
        registry.mark_unsupported("unsupported_configuration")
        raise RecoveryRefused("unsupported_configuration")


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
