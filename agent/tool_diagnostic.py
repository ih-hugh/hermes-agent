"""Run-local, names-only observation of Hermes-managed SDK sends.

No provider request, schema, message, or exception is retained by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from contextvars import ContextVar
from typing import Any

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_MAX_NAMES = 128
_MAX_RECORD_BYTES = 16_384
_MAX_SCHEMA_BYTES = 1_000_000
_MAX_ID_BYTES = 128

# The value is the explicit run-local observer, copied into Hermes request workers.
current_tool_send_observer: ContextVar[ToolSendObserver | None] = ContextVar(
    "current_tool_send_observer", default=None
)


def _safe_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_ID_BYTES
    ):
        raise ValueError("invalid diagnostic identifier")
    if not all(32 <= ord(char) < 127 for char in value):
        raise ValueError("invalid diagnostic identifier")
    # Hermes's internal request ID can include a caller-supplied session ID.
    # Preserve retry correlation without returning or retaining that raw value.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_names(values: object) -> list[str]:
    if not isinstance(values, (list, tuple, frozenset)) or len(values) > _MAX_NAMES:
        raise ValueError("invalid diagnostic names")
    names = list(values)
    if any(not isinstance(name, str) or not _NAME.fullmatch(name) for name in names):
        raise ValueError("invalid diagnostic name")
    if len(names) != len(set(names)):
        raise ValueError("duplicate diagnostic name")
    return names


class ToolSendObserver:
    """One process-local run's bounded SDK-send ledger and closure barrier."""

    def __init__(
        self,
        run_id: str,
        profile: str,
        owner_scope: str,
        pid: int,
        started_at: int,
        *,
        max_attempts: int = 16,
        now: float | None = None,
    ) -> None:
        if pid <= 0 or started_at <= 0:
            raise ValueError("unknown process identity")
        self.run_id = run_id
        self.profile = profile
        self.owner_scope = owner_scope
        self.pid = pid
        self.started_at = started_at
        self.created_at = time.time() if now is None else now
        self.closed_at: float | None = None
        self.max_attempts = max_attempts
        self._lock = threading.RLock()
        self._attempts: list[dict[str, Any]] = []
        self._started = 0
        self._workers = 0
        self._producer_closed = False
        self._reason: str | None = None
        self._expired = False
        self._bytes = 0
        self._assembly_names: tuple[str, ...] | None = None
        self._assembly_active: bool | None = None
        self._scope_names: tuple[str, ...] | None = None
        self._registry_generation: int | None = None
        self._search_config_sha256: str | None = None

    def set_tool_scope(
        self,
        assembly_names: tuple[str, ...],
        scope_names: tuple[str, ...],
        active: bool,
    ) -> None:
        """Freeze the agent's assembled bridge selection at run binding."""
        with self._lock:
            if self._expired:
                return
            try:
                assembly = tuple(_strict_names(assembly_names))
                scope = tuple(_strict_names(scope_names))
                if self._assembly_active is not None and (
                    self._assembly_names != assembly
                    or self._scope_names != scope
                    or self._assembly_active != bool(active)
                ):
                    self._reason = self._reason or "scope_changed"
                    return
                self._assembly_names = assembly
                self._scope_names = scope
                self._assembly_active = bool(active)
                if active and self._assembly_names != self._scope_names:
                    self._reason = self._reason or "scope_changed"
            except (TypeError, ValueError):
                self._reason = self._reason or "capture_failed"

    def register_worker(self) -> None:
        with self._lock:
            if not self._expired:
                if self.closed_at is not None:
                    # A worker discovered after apparent settlement invalidates it.
                    self._reason = self._reason or "capture_failed"
                    self.closed_at = None
                self._workers += 1

    def close_worker(self) -> None:
        with self._lock:
            if self._workers <= 0:
                self._reason = self._reason or "capture_failed"
            else:
                self._workers -= 1
            self._settle_if_closed()

    def close_producer(self) -> None:
        with self._lock:
            self._producer_closed = True
            self._settle_if_closed()

    def _settle_if_closed(self) -> None:
        if self._producer_closed and self._workers == 0 and self.closed_at is None:
            self.closed_at = time.time()

    def mark_incomplete(self, reason: str) -> None:
        if reason not in {
            "capture_failed",
            "scope_changed",
            "unsupported_api_mode",
            "unsupported_call_role",
            "unsupported_configuration",
            "limit_exceeded",
            "unclosed_producer",
        }:
            reason = "capture_failed"
        with self._lock:
            if not self._expired:
                self._reason = self._reason or reason

    def capture_sdk_send(
        self,
        api_request_id: str,
        api_mode: str,
        call_role: str,
        tool_definitions: object,
        *,
        deferred_tool_names: tuple[str, ...],
        tool_search_active: bool,
    ) -> None:
        """Count one entered SDK call before strict extraction; never raise to the caller."""
        with self._lock:
            if self._expired:
                return
            self._started += 1
            index = self._started
            if index > self.max_attempts:
                self._reason = self._reason or "limit_exceeded"
                return
            if api_mode != "chat_completions":
                self._reason = self._reason or "unsupported_api_mode"
                return
            if call_role != "main":
                self._reason = self._reason or "unsupported_call_role"
                return
            try:
                if not isinstance(tool_search_active, bool):
                    raise ValueError("invalid active marker")
                request_id = _safe_identifier(api_request_id)
                if (
                    not isinstance(tool_definitions, list)
                    or len(tool_definitions) > _MAX_NAMES
                ):
                    raise ValueError("invalid schemas")
                names = _strict_names([
                    schema["function"]["name"]
                    for schema in tool_definitions
                    if isinstance(schema, dict)
                    and schema.get("type") == "function"
                    and isinstance(schema.get("function"), dict)
                ])
                if len(names) != len(tool_definitions):
                    raise ValueError("unsupported schema shape")
                deferred = _strict_names(deferred_tool_names)
                if not tool_search_active and deferred:
                    raise ValueError("inactive bridge with deferred names")
                encoded = json.dumps(
                    tool_definitions,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
                if len(encoded) > _MAX_SCHEMA_BYTES:
                    raise ValueError("schema too large")
                attempt = {
                    "api_request_id": request_id,
                    "attempt_index": index,
                    "api_mode": api_mode,
                    "call_role": call_role,
                    "advertised_tool_names": names,
                    "tool_schema_sha256": hashlib.sha256(encoded).hexdigest(),
                    "deferred_tool_names": deferred,
                    "tool_search_active": tool_search_active,
                }
                record_bytes = len(json.dumps(attempt, separators=(",", ":")).encode())
                if self._bytes + record_bytes > _MAX_RECORD_BYTES:
                    self._reason = self._reason or "limit_exceeded"
                    return
                self._bytes += record_bytes
                self._attempts.append(attempt)
            except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
                self._reason = self._reason or "capture_failed"

    def observe_scope(self, names: tuple[str, ...], active: bool) -> None:
        """Compare a fresh send/dispatch read with the binding-time immutable snapshot."""
        with self._lock:
            if self._expired:
                return
            try:
                names = tuple(_strict_names(names))
                if (
                    self._assembly_active is None
                    or bool(active) != self._assembly_active
                ):
                    self._reason = self._reason or "scope_changed"
                elif active and (
                    names != self._assembly_names or names != self._scope_names
                ):
                    self._reason = self._reason or "scope_changed"
            except (TypeError, ValueError):
                self._reason = self._reason or "capture_failed"

    def frozen_scope(self) -> tuple[tuple[str, ...], bool]:
        with self._lock:
            if self._assembly_active is None or self._scope_names is None:
                self._reason = self._reason or "capture_failed"
                return (), False
            return self._scope_names, self._assembly_active

    def set_drift_markers(self, registry_generation: int, config_sha256: str) -> None:
        with self._lock:
            self._registry_generation = registry_generation
            self._search_config_sha256 = config_sha256

    def check_drift_markers(self, registry_generation: int, config_sha256: str) -> None:
        with self._lock:
            if (
                self._registry_generation is None
                or self._search_config_sha256 is None
                or self._registry_generation != registry_generation
                or self._search_config_sha256 != config_sha256
            ):
                self._reason = self._reason or "scope_changed"

    def expire(self) -> None:
        with self._lock:
            self._expired = True
            self._attempts.clear()
            self._bytes = 0
            self._assembly_names = self._scope_names = None
            self._search_config_sha256 = None

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        with self._lock:
            current = time.time() if now is None else now
            if self._expired:
                state = "expired"
            elif self.closed_at is None or not self._producer_closed or self._workers:
                state = "pending"
            elif (
                self._reason
                or self._started == 0
                or len(self._attempts) != self._started
            ):
                state = "incomplete"
            else:
                state = "complete"
            result: dict[str, Any] = {
                "object": "hermes.run.tool_diagnostic",
                "version": "names-v1",
                "run_id": self.run_id,
                "profile": self.profile,
                "process": {"pid": self.pid, "started_at": self.started_at},
                "state": state,
                "attempts": [dict(a) for a in self._attempts],
            }
            if state == "incomplete":
                result["reason"] = self._reason or "capture_failed"
            elif state == "pending" and current >= self.created_at + 3600:
                result["state"] = "incomplete"
                result["reason"] = "unclosed_producer"
            return result
