"""Private names-v1 diagnostic admission, readback, and bounded retention."""

from __future__ import annotations

import time
from typing import Any

try:
    from aiohttp import web
except ImportError:
    web = None  # type: ignore[assignment]

from agent.tool_diagnostic import ToolSendObserver
from gateway.platforms.api_server_room_grants import _json_error

_MAX_RUNS = 256
_NAMES_SECONDS = 900
_ADMISSION_SECONDS = 3600
_TOMBSTONE_SECONDS = 900


def initialize(self) -> None:
    self._run_tool_diagnostics: dict[str, ToolSendObserver] = {}
    self._run_tool_diagnostic_tombstones: dict[str, tuple[str, float]] = {}


def requested_version(body: object) -> tuple[bool, str | None]:
    if not isinstance(body, dict) or "diagnostics" not in body:
        return False, None
    diagnostics = body["diagnostics"]
    if not isinstance(diagnostics, dict) or set(diagnostics) != {"tool_inventory"}:
        return False, "invalid_tool_diagnostic"
    if diagnostics["tool_inventory"] != "names-v1":
        return False, "unsupported_tool_diagnostic"
    return True, None


def admission_error(
    self, request: web.Request, *, _openai_error
) -> web.Response | None:
    sweep(self)
    if self._room_grant_token(request) or request.headers.get("X-Hermes-Room-Grant"):
        return _json_error(
            _openai_error,
            "A profile API bearer is required for tool diagnostics",
            code="tool_diagnostic_auth_required",
            status=401,
        )
    if int(self._run_owner_pid or 0) <= 0 or int(self._run_owner_started or 0) <= 0:
        return _json_error(
            _openai_error,
            "Process identity unavailable for tool diagnostics",
            code="tool_diagnostic_process_unknown",
            status=503,
        )
    return None


def capacity_error(self, *, _openai_error) -> web.Response | None:
    if (
        len(self._run_tool_diagnostics) + len(self._run_tool_diagnostic_tombstones)
        >= _MAX_RUNS
    ):
        return _json_error(
            _openai_error,
            "Tool diagnostic capacity reached",
            code="tool_diagnostic_capacity",
            status=429,
        )
    return None


def create(self, run_id: str, profile: str, owner_scope: str) -> ToolSendObserver:
    observer = ToolSendObserver(
        run_id, profile, owner_scope, self._run_owner_pid, self._run_owner_started
    )
    self._run_tool_diagnostics[run_id] = observer
    return observer


def sweep(self, now: float | None = None) -> None:
    if now is None:
        now = time.time()
    for run_id, observer in list(self._run_tool_diagnostics.items()):
        names_until = min(
            observer.created_at + _ADMISSION_SECONDS,
            (observer.closed_at + _NAMES_SECONDS)
            if observer.closed_at is not None
            else float("inf"),
        )
        if now < names_until:
            continue
        observer.expire()
        self._run_tool_diagnostics.pop(run_id, None)
        if now < names_until + _TOMBSTONE_SECONDS:
            self._run_tool_diagnostic_tombstones[run_id] = (
                observer.owner_scope,
                names_until + _TOMBSTONE_SECONDS,
            )
        self._release_run_owner_if_forgotten(run_id)
    for run_id, (_, expires_at) in list(self._run_tool_diagnostic_tombstones.items()):
        if now >= expires_at:
            self._run_tool_diagnostic_tombstones.pop(run_id, None)
            self._release_run_owner_if_forgotten(run_id)


async def handle_get(self, request: web.Request, *, _api_server) -> web.Response:
    # A room token cannot widen API-key authority, including on a mixed-header request.
    if self._room_grant_token(request) or request.headers.get("X-Hermes-Room-Grant"):
        return _json_error(
            _api_server._openai_error,
            "A profile API bearer is required",
            code="tool_diagnostic_auth_required",
            status=401,
        )
    auth_error = self._check_auth(request)
    if auth_error is not None:
        return auth_error
    sweep(self)
    run_id = request.match_info["run_id"]
    scope = self._run_idempotency_scope(request)
    observer = self._run_tool_diagnostics.get(run_id)
    if observer is not None and observer.owner_scope == scope:
        return web.json_response(observer.snapshot())
    tombstone = self._run_tool_diagnostic_tombstones.get(run_id)
    if tombstone is not None and tombstone[0] == scope:
        return web.json_response(
            {
                "object": "hermes.run.tool_diagnostic",
                "version": "names-v1",
                "run_id": run_id,
                "state": "expired",
                "attempts": [],
            },
            status=410,
        )
    return _json_error(
        _api_server._openai_error, "Run not found", code="run_not_found", status=404
    )
