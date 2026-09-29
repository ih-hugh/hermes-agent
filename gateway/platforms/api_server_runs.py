"""Durable ``/v1/runs`` admission, status, events, and control handlers."""

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
import weakref
from copy import deepcopy
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, cast

try:
    from aiohttp import web
except ImportError:
    web = None  # type: ignore[assignment]
try:
    from aiohttp.web_request import RequestKey
except ImportError:
    # Separate block: aiohttp < 3.14 lacks RequestKey, and a shared except
    # would reset the already-imported ``web`` to None (500 on POST /v1/runs).
    RequestKey = None  # type: ignore[assignment,misc]

from gateway.platforms.api_server_room_grants import _json_error, _room_grant_error_response
from gateway.platforms.api_server_run_idempotency import TERMINAL_STATUSES
from gateway.platforms import api_server_tool_diagnostic as _tool_diag

if TYPE_CHECKING:
    from hermes_state import SessionDB


logger = logging.getLogger("gateway.platforms.api_server")
_ROOM_RETENTION_REQUEST_KEY = (
    RequestKey("hermes.room_run_retention_until", float) if RequestKey is not None
    else "hermes.room_run_retention_until")
# Forwarded subagent lifecycle fields; free-text ones are secret-redacted.
_SUBAGENT_EVENT_KEYS = (
    "goal", "task_count", "task_index", "subagent_id", "child_session_id", "delegation_id", "parent_id",
    "depth", "model", "tool_count", "status", "summary", "duration_seconds", "input_tokens",
    "output_tokens", "reasoning_tokens", "api_calls", "cost_usd", "files_read", "files_written",
    "output_tail")
_SUBAGENT_TEXT_KEYS = ("goal", "summary", "output_tail")
# Terminal usage payload: (wire key, agent attribute), in wire order.
_USAGE_FIELDS = (
    ("input_tokens", "session_prompt_tokens"), ("output_tokens", "session_completion_tokens"),
    ("total_tokens", "session_total_tokens"))
_COLD_PROTECTED_STATUS_SECONDS = 5.0
# Tool-progress event -> SSE payload fields (tool_name, preview, kwargs); key order is wire format.
_FIXED_EVENT_FIELDS = {
    "tool.started": lambda tool, preview, kw: {"tool": tool, "preview": preview},
    "tool.completed": lambda tool, preview, kw: {
        "tool": tool, "duration": round(kw.get("duration", 0), 3), "error": kw.get("is_error", False)},
    "reasoning.available": lambda tool, preview, kw: {"text": preview or ""}}


def _remember_room_retention(request: "web.Request", claims: dict[str, Any]) -> None:
    value = float(claims.get("status_expires_at") or claims.get("expires_at") or 0)
    try:
        request[_ROOM_RETENTION_REQUEST_KEY] = value
    except (AttributeError, TypeError):
        setattr(request, "_hermes_room_run_retention_until", value)


def _room_retention_until(request: "web.Request") -> float:
    try:
        value = request.get(_ROOM_RETENTION_REQUEST_KEY, 0)
    except AttributeError:
        value = getattr(request, "_hermes_room_run_retention_until", 0)
    return max(0.0, float(value or 0))


def _run_event(run_id: str, name: str, **fields: Any) -> Dict[str, Any]:
    """Build one SSE event payload (key order is part of the wire format)."""
    return {"event": name, "run_id": run_id, "timestamp": time.time(), **fields}


def _run_not_found(_openai_error, run_id: str) -> "web.Response":
    return _json_error(_openai_error, f"Run not found: {run_id}", code="run_not_found", status=404)


def _uses_room_run_auth(self, request: "web.Request") -> bool:
    return request.path.endswith("/v1/runs") and bool(self._room_grant_token(request))


def _initialize_run_state(self, *, store_factory) -> None:
    """Initialize adapter-owned durable and live ``/v1/runs`` state."""
    self._run_idempotency_store = store_factory()
    self._run_owner_pid = os.getpid()
    try:
        from gateway.status import get_process_start_time
        self._run_owner_started = int(get_process_start_time(self._run_owner_pid) or 0)
    except Exception:
        self._run_owner_started = 0
    # All keyed by run_id: SSE queues (+creation time for the TTL sweep), connected
    # subscribers, live agent/task refs for cooperative stop (the executor thread may
    # outlive the request, hence the separate stopping set), pollable statuses, and
    # approval session keys (approval core resolves by session key, clients by run_id).
    self._run_idempotency_ids: set[str] = set()
    self._protected_run_ids: set[str] = set()
    self._protected_run_stores: dict[str, Any] = {}
    self._protected_physical_owners: dict[str, tuple[Any, str]] = {}
    self._protected_run_registries: dict[str, Any] = {}
    # Small process-local identity only; heavy run/registry state retires at its barrier.
    self._protected_provider_identities: dict[object, tuple[weakref.ReferenceType, bytes]] = {}
    self._protected_status_tasks: dict[str, asyncio.Task[None]] = {}
    # A listener's cold ordinary claims must not inspect the still-empty
    # SQLite inode another request in that listener is bootstrapping.
    self._ordinary_claim_lock = asyncio.Lock()
    self._run_stream_subscribers: set[str] = set()
    self._stopping_run_ids: set[str] = set()
    (
        self._run_owners, self._run_streams, self._run_streams_created, self._active_run_agents,
        self._active_run_tasks, self._run_statuses, self._run_approval_sessions,
    ) = ({} for _ in range(7))
    _tool_diag.initialize(self)


def _http_routes(self) -> list[tuple[str, str, Any]]:
    return [
        ("POST", "/v1/runs", self._handle_runs), ("GET", "/v1/runs/{run_id}", self._handle_get_run),
        ("GET", "/v1/runs/{run_id}/events", self._handle_run_events),
        ("GET", "/v1/runs/{run_id}/tool-diagnostic", self._handle_run_tool_diagnostic),
        ("POST", "/v1/runs/{run_id}/approval", self._handle_run_approval),
        ("POST", "/v1/runs/{run_id}/steer", self._handle_steer_run),
        ("POST", "/v1/runs/{run_id}/stop", self._handle_stop_run)]


def _idempotency_capabilities(self, *, store_type) -> dict[str, Any]:
    return {
        "supported": True,
        "durable": self._run_idempotency_store.durable,
        "retention_seconds": store_type.RETENTION_SECONDS}


def _close_run_state(self) -> None:
    try:
        if getattr(self, "_run_idempotency_store", None) is not None:
            self._run_idempotency_store.close()
    except Exception:
        logger.debug("Failed to close run idempotency store for %s", self.name, exc_info=True)


async def _await_protected_status(self, run_id: str) -> None:
    """Join ordered status writes until the run's tail stays unchanged.

    Shielding leaves a SQLite worker tracked and its outcome observable if the
    HTTP caller or executor coroutine is cancelled while a writer holds the DB.
    The producer must quiesce its callbacks before using this as a close barrier.
    """
    while (task := self._protected_status_tasks.get(run_id)) is not None:
        await asyncio.shield(task)
        if self._protected_status_tasks.get(run_id) is task:
            return


async def _drain_protected_status(self) -> None:
    """Join tracked status workers before the adapter closes its SessionDBs."""
    lanes = getattr(self, "_protected_status_tasks", {})
    while tasks := dict(lanes):
        outcomes = await asyncio.gather(*(asyncio.shield(task) for task in tasks.values()),
                                        return_exceptions=True)
        if len(tasks) == len(lanes) and all(lanes.get(run_id) is task for run_id, task in tasks.items()):
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    logger.error("[api_server] protected status persistence failed during disconnect")
            return


def _queue_protected_status(self, run_id: str, status: Dict[str, Any]) -> None:
    """Serialize durable snapshots for one run without waiting on the API loop."""
    loop = asyncio.get_running_loop()
    previous = self._protected_status_tasks.get(run_id)
    store = self._protected_run_stores[run_id]
    snapshot = deepcopy(status)

    async def _persist() -> None:
        if previous is not None:
            await asyncio.shield(previous)
        await asyncio.to_thread(store.update_status, run_id, snapshot)

    self._protected_status_tasks[run_id] = loop.create_task(_persist())


def _set_run_status(self, run_id: str, status: str, **fields: Any) -> Dict[str, Any]:
    """Update pollable run status without exposing private agent objects."""
    now = time.time()
    current = self._run_statuses.get(run_id, {})
    previous_status = str(current.get("status") or "")
    field_names = set(fields)
    current.update({"object": "hermes.run", "run_id": run_id, "status": status, "updated_at": now})
    current.setdefault("created_at", fields.pop("created_at", now))
    current.update(fields)
    if status != "waiting_for_approval":
        current.pop("approval", None)
    self._run_statuses[run_id] = current
    should_persist = (
        status != previous_status
        or status in TERMINAL_STATUSES
        or bool(field_names & {"output", "error", "usage", "pending_steer", "session_id", "approval"}))
    if run_id in self._run_idempotency_ids and should_persist:
        try:
            self._run_idempotency_store.update_status(run_id, current)
        except Exception:
            logger.exception("[api_server] failed to persist idempotent run status %s", run_id)
    if run_id in self._protected_run_ids and should_persist:
        # Callers that acknowledge dispatch, stop or completion join this lane.
        # Failures remain on the tracked task and block every later write.
        _queue_protected_status(self, run_id, current)
    return current


def _schedule_run_callback(self, run_id: str, loop: "asyncio.AbstractEventLoop", callback) -> None:
    """Inventory a callback before enqueue, including during active-parent closing."""
    registry = self._protected_run_registries.get(run_id)
    if registry is None:
        if run_id in self._protected_run_ids:
            from hermes_state_recovery import RecoveryRefused
            raise RecoveryRefused("producer_closed")
        with suppress(Exception):
            loop.call_soon_threadsafe(callback)
        return
    from agent.recovery_producers import current_lease
    parent = current_lease() or registry.permit
    lease = registry.enter(parent, "callback")
    try:
        loop.call_soon_threadsafe(lambda: lease.run(callback))
    except BaseException:
        lease.cancel_before_start()
        raise


def _selected_provider_capture_for_scope(self, scope, store):
    """Reacquire a lightweight same-process selected identity after run transport pruning."""
    from hermes_state_recovery import RecoveryRefused
    from hermes_state_recovery_provider import ProviderLedger, SelectedProviderCapture

    retained = self._protected_provider_identities.get(scope)
    if retained is None or retained[0]() is None:
        raise RecoveryRefused("provider_identity_unavailable")
    admission = ProviderLedger(store).admission(scope)
    if admission.canonical_bytes() != retained[1]:
        raise RecoveryRefused("provider_admission_mismatch")
    capture = SelectedProviderCapture(admission, retained[0]())
    capture.require_selected()
    return capture


def _retire_selected_provider_identity(self, scope) -> None:
    """Called only after a committed seal or explicit abandoned-session retirement."""
    self._protected_provider_identities.pop(scope, None)


def _make_run_event_callback(self, run_id: str, loop: "asyncio.AbstractEventLoop", *, _api_server):
    """Return a callback that pushes structured events to the run SSE queue."""
    redact_sensitive_text = _api_server.redact_sensitive_text

    def _push(event: Dict[str, Any]) -> None:
        def _publish() -> None:
            current = self._run_statuses.get(run_id)
            if current is not None and current.get("status") not in TERMINAL_STATUSES | {"stopping"}:
                self._set_run_status(run_id, current["status"], last_event=event.get("event"))
            q = self._run_streams.get(run_id)
            if q is not None:
                with suppress(Exception):
                    q.put_nowait(event)

        _schedule_run_callback(self, run_id, loop, _publish)

    def _callback(event_type: str, tool_name: str = None, preview: str = None, args=None, **kwargs):
        # _thinking / subagent.tool / subagent_progress are deliberately dropped (UI noise);
        # lifecycle boundaries must land so clients can observe delegate_task failures.
        fields = _FIXED_EVENT_FIELDS.get(event_type)
        if fields is not None:
            _push(_run_event(run_id, event_type, **fields(tool_name, preview, kwargs)))
        elif event_type in {"subagent.start", "subagent.complete"}:
            event = _run_event(run_id, event_type)
            if preview is not None:
                event["preview"] = redact_sensitive_text(str(preview), force=True)
            for key in _SUBAGENT_EVENT_KEYS:
                value = kwargs.get(key)
                if value is not None:
                    # Free text may carry child tool output: force secret redaction on this public stream.
                    redact = key in _SUBAGENT_TEXT_KEYS and isinstance(value, str)
                    event[key] = redact_sensitive_text(value, force=True) if redact else value
            _push(event)

    return _callback


def _room_permission_for(request: "web.Request") -> str:
    if request.path.endswith("/stop"):
        return "stop"
    if request.path.endswith("/approval"):
        return "approve"
    return "status" if request.method == "GET" else "dispatch"


def _run_idempotency_scope(self, request: "web.Request", *, _api_server) -> str:
    """Opaque auth/profile namespace; never persist bearer credentials."""
    if self._room_grant_token(request):
        claims = self._room_grant_claims(request, permission=_room_permission_for(request))
        _remember_room_retention(request, claims)
        parts = (claims[k] for k in (
            "room_id", "home_install_id", "authority_gateway_id", "authority_epoch",
            "member_id", "target_install_id", "target_profile"))
    else:
        parts = (_api_server._api_request_profile.get() or "default",
                 self._expected_api_key() or "unauthenticated-test-listener")
    return hashlib.sha256("\0".join(map(str, parts)).encode()).hexdigest()


def _check_run_auth(self, request: "web.Request", *, permission: str, _api_server) -> "web.Response | None":
    if not self._room_grant_token(request):
        return self._check_auth(request)
    try:
        self._room_grant_claims(request, permission=permission)
    except Exception as exc:
        return _room_grant_error_response(exc, _openai_error=_api_server._openai_error)
    return None


def _owner_alive(owner_pid: int, owner_started: int) -> bool:
    """True when the recorded owner pid still exists and is the same process incarnation."""
    try:
        from gateway.status import _pid_exists, get_process_start_time
        return owner_pid > 0 and bool(_pid_exists(owner_pid)) and (
            not owner_started or int(get_process_start_time(owner_pid) or 0) == owner_started)
    except Exception:
        return False


def _durable_run_status(self, request: "web.Request", run_id: str) -> Dict[str, Any] | None:
    """Hydrate a scoped run status and fail stale owners closed."""
    status = self._run_statuses.get(run_id)
    if status is not None:
        if run_id in self._run_idempotency_ids:
            scope = self._run_idempotency_scope(request)
            self._run_idempotency_store.extend_retention(scope, run_id, _room_retention_until(request))
        return status
    scope = self._run_idempotency_scope(request)
    record = self._run_idempotency_store.status_for_run(
        scope, run_id, retention_until=_room_retention_until(request))
    if record is None:
        return None
    status = dict(record["status"])
    if status.get("status") not in TERMINAL_STATUSES and not _owner_alive(
        int(record.get("owner_pid") or 0), int(record.get("owner_started") or 0)):
        status.update(
            status="interrupted", error="The gateway restarted before this run settled.",
            last_event="run.interrupted", updated_at=time.time())
        self._run_idempotency_store.update_status(run_id, status)
    self._run_statuses[run_id] = status
    self._run_idempotency_ids.add(run_id)
    self._run_owners[run_id] = scope
    return status


def _resolve_conversation_history(
    self, body: dict, raw_input: Any, *, _openai_error
) -> "tuple[List[Dict[str, str]], Any, Any, web.Response | None]":
    """Return ``(history, instructions, stored_session_id, error)``; precedence:
    ``conversation_history`` > ``previous_response_id`` chain > all-but-last ``input`` messages."""
    instructions = body.get("instructions")
    previous_response_id = body.get("previous_response_id")
    conversation_history: List[Dict[str, str]] = []
    raw_history = body.get("conversation_history")
    if raw_history:
        if not isinstance(raw_history, list):
            return [], instructions, None, _json_error(
                _openai_error, "'conversation_history' must be an array of message objects", status=400)
        for i, entry in enumerate(raw_history):
            if not isinstance(entry, dict) or {"role", "content"} - set(entry):
                return [], instructions, None, _json_error(
                    _openai_error, f"conversation_history[{i}] must have 'role' and 'content' fields",
                    status=400)
            conversation_history.append({"role": str(entry["role"]), "content": str(entry["content"])})
        if previous_response_id:
            logger.debug("Both conversation_history and previous_response_id provided; using conversation_history")
    stored_session_id = None
    if not conversation_history and previous_response_id:
        stored = self._response_store.get(previous_response_id)
        if stored:
            conversation_history = list(stored.get("conversation_history", []))
            stored_session_id = stored.get("session_id")
            if instructions is None:
                instructions = stored.get("instructions")
    if not conversation_history and isinstance(raw_input, list) and len(raw_input) > 1:
        for msg in raw_input[:-1]:
            if isinstance(msg, dict) and msg.get("role") and msg.get("content"):
                content = msg["content"]
                if isinstance(content, list):  # flatten multi-part content blocks to text
                    content = " ".join(p.get("text", "") for p in content
                                       if isinstance(p, dict) and p.get("type") == "text")
                conversation_history.append({"role": msg["role"], "content": str(content)})
    return conversation_history, instructions, stored_session_id, None


def _accepted_response(run_id: str, status: str, gateway_session_key, *, replayed: bool) -> "web.Response":
    """202 admission response; replays are flagged via ``Idempotency-Replayed``."""
    headers = {"Idempotency-Replayed": "true"} if replayed else {}
    if gateway_session_key:
        headers["X-Hermes-Session-Key"] = gateway_session_key
    return web.json_response(
        {"run_id": run_id, "status": status, "replayed": replayed}, status=202, headers=headers)


def _replay_or_conflict(self, request, outcome, record, gateway_session_key, _openai_error) -> "web.Response":
    """409 for a fingerprint conflict, else a 202 replay of the already-admitted run."""
    if outcome == "conflict":
        return _json_error(
            _openai_error, "Idempotency-Key was already used with a different request payload",
            code="idempotency_key_conflict", status=409)
    original_id = str(record["run_id"])
    status = self._durable_run_status(request, original_id) or record["status"]
    return _accepted_response(original_id, status.get("status", "queued"), gateway_session_key, replayed=True)


@dataclass(slots=True)
class _RunLaunch:
    """State for an admitted run's background task; contextvars are captured here
    because the task outlives the request (and its middleware profile scope)."""

    owner: Any
    run_id: str
    queue: "asyncio.Queue[Optional[Dict]]"
    session_id: str
    gateway_session_key: Optional[str]
    declared_selected: bool
    user_message: str
    conversation_history: List[Dict[str, str]]
    # #98619: only continuation paths that reload session history may grant wake authority —
    # a previous_response_id continuation consumes its ResponseStore snapshot instead, and a
    # caller-supplied conversation_history is authoritative for the turn; neither consumes a
    # SessionDB delivery row, so both stay default-denied.
    session_history_delivery: bool
    agent_kwargs: dict  # ``_create_agent`` keyword arguments (prompt, model overrides, route, room policy)
    request_profile: Any
    browser_control_principal: Any
    browser_control_transport_family: Any
    turn_author: Optional[Dict[str, Any]] = None  # memory-attribution label only; grants nothing
    tool_observer: Any = None
    recovery_handoff: object | None = None  # one-use, process-local authority from committed admission
    recovery_provider_capture: object | None = None  # selected source-bound plugin object and attestation
    recovery_runtime: Any = None  # private B2a static constructor input; never serialized
    recovery_registry: Any = None
    recovery_write_permit: Any = None
    recovery_status_barrier: Any = None
    recovery_execution_settled: Any = None
    recovery_coroutine_settled: Any = None

    @property
    def approval_session_key(self) -> str:
        # Isolated per run: session ids are conversation scopes, not authorization namespaces.
        return self.run_id

    def put_event(self, event: Optional[Dict]) -> None:
        """Enqueue only while this run still owns live transport state."""
        if self.owner._run_streams.get(self.run_id) is self.queue:
            self.queue.put_nowait(event)


@dataclass(frozen=True, slots=True)
class _ProtectedNewAdmission:
    db: Any
    store: Any
    scope: Any
    runtime: Any
    provider_capture: Any
    history: list[dict[str, str]]
    result: Any
    replay_status: str | None


def _bounded_protected_history(db: "SessionDB", session_id: str) -> list[dict[str, Any]]:
    """Decode an exact active-row snapshot only after bounding every source cell."""
    from gateway.platforms.api_server_recovery_artifacts import (
        MAX_RESPONSE_BYTES, MAX_SNAPSHOT_BYTES, MAX_TRANSCRIPT_ROWS,
    )
    from hermes_state_recovery import RecoveryRefused
    from hermes_state_recovery_deadline import require_time

    columns = tuple(part.strip() for part in db._CONVERSATION_ROW_COLUMNS.split(","))
    payload_columns = tuple(column for column in columns if column != "id")
    byte_terms = (
        f"coalesce(length(substr(CAST({column} AS BLOB),1,{MAX_RESPONSE_BYTES + 1})),0)"
        for column in payload_columns
    )
    metadata_sql = (
        "SELECT id," + "+".join(byte_terms)
        + " FROM messages WHERE session_id=? AND active=1 ORDER BY id LIMIT ?"
    )
    rows_sql = (
        f"SELECT {db._CONVERSATION_ROW_COLUMNS} FROM messages "
        "WHERE session_id=? AND active=1 ORDER BY id"
    )

    def _read(conn: sqlite3.Connection) -> list[dict[str, Any]]:
        require_time()
        if conn.in_transaction:
            raise RecoveryRefused("protected_history_unavailable")
        conn.execute("BEGIN")
        try:
            source_bytes = 0
            count = 0
            last_id = 0
            for row in conn.execute(metadata_sql, (session_id, MAX_TRANSCRIPT_ROWS + 1)):
                require_time()
                row_id, row_bytes = row
                if (type(row_id) is not int or row_id <= last_id
                        or type(row_bytes) is not int or row_bytes < 0
                        or row_bytes > MAX_RESPONSE_BYTES
                        or count >= MAX_TRANSCRIPT_ROWS):
                    raise RecoveryRefused("protected_history_oversized")
                source_bytes += row_bytes
                if source_bytes > MAX_SNAPSHOT_BYTES:
                    raise RecoveryRefused("protected_history_oversized")
                count += 1
                last_id = row_id
            require_time()
            rows = conn.execute(rows_sql, (session_id,)).fetchall()
            require_time()
            if len(rows) != count:
                raise RecoveryRefused("protected_history_changed")
            history = db._rows_to_conversation(
                rows, session_id=session_id, include_ancestors=False,
                repair_alternation=False,
            )
            require_time()
            output_bytes = 0
            for chunk in json.JSONEncoder(ensure_ascii=False, separators=(",", ":")).iterencode(history):
                require_time()
                output_bytes += len(chunk.encode("utf-8"))
                if output_bytes > MAX_SNAPSHOT_BYTES:
                    raise RecoveryRefused("protected_history_oversized")
            return history
        finally:
            conn.execute("ROLLBACK")

    return db._read_retrying_ioerr(_read)


def _prepare_and_reserve_protected(
    adapter, owner, body: dict[str, Any], recovery_admission, key: str,
    fingerprint: str, run_id: str, initial_status: dict[str, Any], deadline: float,
) -> _ProtectedNewAdmission:
    """One bounded worker owns all new-request source and reserve effects."""
    from pathlib import Path

    from agent.recovery_context import current_incarnation
    from gateway.platforms.api_server_recovery_runtime import prepare_static_chat_runtime
    from hermes_state_recovery import AdmissionIdentity, RecoveryRefused, RecoveryScope, RecoveryStore
    from hermes_state_recovery_deadline import require_time
    from hermes_state_recovery_provider import capture_selected_provider_admission

    require_time()
    runtime = prepare_static_chat_runtime(owner, session_id=body["session_id"])
    require_time()
    if (("model" in body and body["model"] != runtime.model)
            or ("provider" in body and body["provider"] != runtime.provider)):
        raise RecoveryRefused("unsupported_configuration")
    capture = capture_selected_provider_admission(body["session_id"], deadline=deadline)
    require_time()
    if capture.provider is not runtime.selected_provider:
        raise RecoveryRefused("provider_selection_changed")
    capture.require_selected()
    require_time()
    db = adapter._open_and_cache_session_db(owner.home)
    if Path(db.db_path).resolve() != (owner.home / "state.db").resolve():
        raise RecoveryRefused("protected_session_authority_unavailable")
    require_time()
    store = RecoveryStore(db)
    scope = RecoveryScope(store.store_id, owner.profile, owner.scope_digest, body["session_id"])
    history = (
        [] if recovery_admission.generation == 0
        else _bounded_protected_history(db, body["session_id"])
    )
    if type(history) is not list:
        raise RecoveryRefused("protected_history_unavailable")
    require_time()
    result = store.reserve(
        recovery_admission,
        AdmissionIdentity(scope, key, fingerprint, run_id, current_incarnation(),
                          capture.admission, initial_status),
    )
    replay_status = None
    if result.outcome == "replayed":
        require_time()
        if result.member is None:
            raise RecoveryRefused("protected_status_unavailable")
        status = store.status_for_run(scope.profile, scope.scope_digest, result.member.run_id)
        if status is None or type(status.get("status")) is not str:
            raise RecoveryRefused("protected_status_unavailable")
        replay_status = status["status"]
    # Once reserve commits, return its actual result even when COMMIT crossed
    # the deadline. The retained HTTP continuation owns the one-use handoff.
    return _ProtectedNewAdmission(db, store, scope, runtime, capture, history, result, replay_status)


async def _settle_undispatched_protected(
    admission: _ProtectedNewAdmission, run_id: str, initial_status: dict[str, Any],
    *, reason: str, permit=None, registry=None, barrier=None,
) -> None:
    """Retain a committed member as explicitly incomplete if dispatch never starts."""
    from agent.recovery_context import issue_producer_permit

    def _settle() -> None:
        producer_permit = permit
        if registry is None:
            if producer_permit is None:
                producer_permit = issue_producer_permit(
                    admission.store, admission.result.handoff,
                )
            admission.store.mark_incomplete(admission.scope, run_id, producer_permit, reason)
        else:
            registry.mark_unsupported(reason)
            if barrier is not None:
                barrier.cancel_before_start()
            registry.request_close()
        admission.store.update_status(
            run_id,
            {**initial_status, "status": "failed", "updated_at": time.time(),
             "error": "Protected admission did not dispatch"},
        )

    # Settlement can outlive the request's five seconds. It owns the actual
    # committed handoff; cancelling the waiter must not discard that authority.
    await asyncio.shield(asyncio.to_thread(_settle))


def _forget_run(self, run_id: str, *tables) -> None:
    """Drop *run_id* from the given run-keyed dicts/sets, then release its owner stamp."""
    for table in tables:
        (table.discard if isinstance(table, set) else lambda k: table.pop(k, None))(run_id)
    self._release_run_owner_if_forgotten(run_id)


def _retire_live_run(self, run_id: str) -> None:
    """Retire agent/task/approval control state once the executor-backed task is done."""
    _forget_run(self, run_id, self._active_run_agents, self._active_run_tasks, self._run_approval_sessions,
                self._stopping_run_ids)


def _drop_run_transport(self, run_id: str) -> None:
    _forget_run(self, run_id, self._run_streams, self._run_streams_created)


async def _resolve_live_session_id(self, session_id: str) -> str:
    """Adopt the live compression-continuation tip for a client-addressed session (#98619):
    a /v1/runs run bound to a pre-rotation id would otherwise load a stale history slice and
    write its turn into the closed parent (CompressionSessionClosedError). Same canonical
    resolution ``/api/sessions/{id}/messages`` reads use; fails open to the original id."""
    db = await self._ensure_session_db_async()
    resolver = getattr(db, "resolve_resume_session_id", None) if db is not None else None
    if not callable(resolver):
        return session_id
    try:
        resolved = await asyncio.to_thread(resolver, session_id)
        return str(resolved) if resolved else session_id
    except Exception:
        logger.debug("/v1/runs live-session resolve failed for %s", session_id, exc_info=True)
        return session_id


async def _handle_runs(self, request: "web.Request", *, _api_server) -> "web.Response":
    """POST /v1/runs — start an agent run, return run_id immediately."""
    _openai_error = _api_server._openai_error
    # Long-term memory scope header (see chat_completions for details).
    gateway_session_key, key_err = self._parse_session_key_header(request)
    if key_err is not None:
        return key_err
    protected_key = request.headers.get("Idempotency-Key", "").strip().startswith("byf-recovery-v1:")
    try:
        if protected_key:
            # StreamReader.read(n) may return a fragment before EOF. Count actual
            # wire bytes, including whitespace, and stop before JSON decoding.
            limit = 16 * 1024
            raw = bytearray()
            while len(raw) <= limit:
                fragment = await request.content.read(min(4096, limit + 1 - len(raw)))
                if not fragment:
                    break
                raw.extend(fragment)
            if len(raw) > limit:
                return _json_error(_openai_error, "Protected request body too large",
                                   code="recovery_body_too_large", status=413)
            from gateway.platforms.api_server_recovery_artifacts import strict_json_loads
            decoded = strict_json_loads(bytes(raw), max_bytes=limit)
            if type(decoded) is not dict:
                return _json_error(_openai_error, "Protected body must be an object",
                                   code="invalid_recovery_admission", status=400)
            body = cast(dict[str, Any], decoded)
        else:
            body = await request.json()
    except Exception:
        return _json_error(_openai_error, "Invalid JSON", status=400)
    # Protected execution is opened only by the served runtime instrumentation
    # (producer, tool, SDK and write guards). Until that runtime is installed,
    # no request flag can turn a reservation into an untracked dispatch.
    requested_recovery = isinstance(body, dict) and "recovery" in body
    recovery_admission = None
    recovery_owner = None
    prepared_runtime = None
    provider_capture = None
    if protected_key or requested_recovery:
        from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
        if not protected_key or not requested_recovery:
            return _json_error(_openai_error, "Protected recovery key and body must be paired",
                               code="recovery_admission_mismatch", status=400)
        try:
            recovery_admission = RecoveryAdmission.model_validate(body["recovery"])
            if (not isinstance(body.get("session_id"), str) or not body["session_id"]
                    or (recovery_admission.generation == 0) != (recovery_admission.parent_run_id is None)):
                raise ValueError("invalid protected recovery request")
        except (ValueError, TypeError):
            return _json_error(_openai_error, "Invalid protected recovery admission",
                               code="invalid_recovery_admission", status=400)
        try:
            session_id_bytes = len(body["session_id"].encode("utf-8"))
        except UnicodeError:
            session_id_bytes = 0
        protected_fields = {"input", "session_id", "recovery", "instructions", "model", "provider"}
        if (
            type(body) is not dict
            or set(body) - protected_fields
            or type(body.get("input")) is not str
            or not body["input"]
            or len(body["input"].encode("utf-8")) > 16_384
            or type(body.get("session_id")) is not str
            or not 0 < len(body["session_id"]) <= 128
            or not 0 < session_id_bytes <= 255
            or ("instructions" in body and type(body["instructions"]) is not str)
            or ("model" in body and type(body["model"]) is not str)
            or ("provider" in body and type(body["provider"]) is not str)
            or gateway_session_key is not None
        ):
            return _json_error(_openai_error, "Unsupported protected request shape",
                               code="recovery_request_unsupported", status=400)
        key_values = request.headers.getall("Idempotency-Key", [])
        if (
            len(key_values) != 1
            or key_values[0] != key_values[0].strip()
            or not key_values[0].startswith("byf-recovery-v1:")
            or not 1 <= len(key_values[0]) <= 255
            or any(ord(char) < 33 or ord(char) > 126 for char in key_values[0])
        ):
            return _json_error(_openai_error, "Invalid protected idempotency key",
                               code="invalid_idempotency_key", status=400)
        from gateway.platforms.api_server_recovery import (
            RecoveryHttpRefused, capture_owner_context,
        )
        from gateway.platforms import api_server as _api_server_module

        try:
            recovery_owner = capture_owner_context(
                self, request, selected_profile=_api_server_module._api_request_profile.get()
            )
        except RecoveryHttpRefused as exc:
            return _json_error(_openai_error, "Protected owner unavailable",
                               code=exc.code, status=exc.status)
        from gateway.platforms.api_server_recovery import (
            RecoveryHttpRefused, _collect_async_result, read_protected_key,
        )
        from hermes_state_recovery_deadline import RecoveryDeadlineExceeded, require_time
        from hermes_state_recovery import RecoveryRefused

        protected_key_value = key_values[0]
        deadline = _api_server_module._api_protected_deadline.get()
        if deadline is None:
            # Direct handler tests lack the HTTP admission wrapper.
            deadline = time.monotonic() + 5.0
        protected_fingerprint = hashlib.sha256(json.dumps(
            {"body": body, "gateway_session_key": ""}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        def _read_existing_key(_worker_deadline: float):
            require_time()
            legacy = self._run_idempotency_store.has_key(
                recovery_owner.scope_digest, protected_key_value,
            )
            require_time()
            if legacy:
                return True, None
            prior = read_protected_key(
                recovery_owner, body["session_id"], protected_key_value,
                protected_fingerprint, recovery_admission,
            )
            return False, prior

        try:
            work = self._recovery_workers.submit(_read_existing_key, deadline=deadline)
            wrapped = asyncio.wrap_future(work.future)
            wrapped.add_done_callback(_collect_async_result)
            legacy_collision, prior = await asyncio.shield(wrapped)
        except (RecoveryHttpRefused, RecoveryDeadlineExceeded, RecoveryRefused,
                sqlite3.DatabaseError, OSError):
            return _json_error(_openai_error, "Protected state store unavailable",
                               code="recovery_store_unavailable", status=503)
        if legacy_collision:
            return _json_error(_openai_error, "Legacy key collision",
                               code="recovery_legacy_collision", status=409)
        if prior is not None:
            if prior.outcome == "conflict":
                return _json_error(_openai_error, "Protected key conflict",
                                   code="idempotency_key_conflict", status=409)
            return _accepted_response(prior.run_id, prior.status, None, replayed=True)
    if recovery_admission is None:
        body, room_error = await self._normalize_room_dispatch(request, body)
        if room_error is not None:
            return room_error
    diagnostic_requested, diagnostic_error = _tool_diag.requested_version(body)
    if diagnostic_error is not None:
        return _json_error(_openai_error, "Unsupported tool diagnostic request",
                           code=diagnostic_error, status=400)
    if diagnostic_requested:
        error = _tool_diag.admission_error(self, request, _openai_error=_openai_error)
        if error is not None:
            return error
    room_dispatch, room_execution_policy = (
        v if isinstance(v, dict) else None for v in (
            (body.get("hosted_room_dispatch"), body.get("_room_execution_policy"))
            if isinstance(body, dict) else (None, None)))
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if len(idempotency_key) > 255 or any(ord(ch) < 33 or ord(ch) > 126 for ch in idempotency_key):
        return _json_error(
            _openai_error, "Idempotency-Key must be 1-255 visible ASCII characters",
            code="invalid_idempotency_key", status=400)
    idempotency_scope = idempotency_fingerprint = ""
    if idempotency_key:
        idempotency_scope = self._run_idempotency_scope(request)
        idempotency_fingerprint = hashlib.sha256(json.dumps(
            {"body": body, "gateway_session_key": gateway_session_key or ""},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
    if recovery_owner is not None and (
        idempotency_scope != recovery_owner.scope_digest
        or idempotency_fingerprint != protected_fingerprint
    ):
        return _json_error(_openai_error, "Protected owner scope changed",
                           code="recovery_owner_changed", status=503)
    raw_input = body.get("input")
    if not raw_input:
        return _json_error(_openai_error, "Missing 'input' field", status=400)
    if isinstance(raw_input, str):
        user_message = raw_input
    else:
        user_message = raw_input[-1].get("content", "") if isinstance(raw_input, list) else ""
    if not user_message:
        return _json_error(_openai_error, "No user message found in input", status=400)
    try:
        turn_author = _api_server._request_turn_author(body)
    except ValueError as exc:
        return _json_error(_openai_error, str(exc), code="invalid_author", status=400)
    conversation_history, instructions, stored_session_id, history_err = (
        _resolve_conversation_history(self, body, raw_input, _openai_error=_openai_error))
    if history_err is not None:
        return history_err
    previous_response_id = body.get("previous_response_id")
    session_id = body.get("session_id") or stored_session_id
    route = self._resolve_route(body.get("model")) if recovery_admission is None else None
    agent_overrides = (
        _api_server._request_agent_overrides(body, virtual_model=self._model_name)
        if recovery_admission is None else {}
    )
    if recovery_admission is None:
        selection_error = self._request_route_conflict_error(
            session_id=session_id, gateway_session_key=gateway_session_key,
            requested_model=agent_overrides.get("requested_model"),
            requested_provider=agent_overrides.get("requested_provider"), route=route)
        if selection_error:
            return _json_error(_openai_error, selection_error, status=400)
    # A lost-acceptance replay must resolve even while the original run holds the last
    # concurrency slot; this read reserves nothing (the atomic reserve below closes the race).
    protected_store = protected_scope = None
    recovery_handoff = None
    recovery_registry = recovery_status_barrier = None
    recovery_write_permit = None
    if recovery_admission is None and idempotency_key:
        outcome, record = self._run_idempotency_store.lookup(
            idempotency_scope, idempotency_key, idempotency_fingerprint,
            retention_until=_room_retention_until(request))
        if outcome == "conflict" or (outcome == "reused" and record is not None):
            return _replay_or_conflict(self, request, outcome, record, gateway_session_key, _openai_error)
    if diagnostic_requested:
        error = _tool_diag.capacity_error(self, _openai_error=_openai_error)
        if error is not None:
            return error
    # Enforce concurrency only for a genuinely new run.
    limited = self._concurrency_limited_response()
    if limited is not None:
        return limited
    run_id = f"run_{uuid.uuid4().hex}"
    protected_new = None
    if recovery_admission is not None:
        from gateway.platforms.api_server_recovery import (
            RecoveryHttpRefused, _collect_async_result,
        )
        from hermes_state_recovery import RecoveryRefused
        from hermes_state_recovery_deadline import RecoveryDeadlineExceeded
        if recovery_owner is None:
            return _json_error(_openai_error, "Protected owner unavailable",
                               code="recovery_owner_changed", status=503)
        created_at = time.time()
        initial_status = {
            "object": "hermes.run", "run_id": run_id, "status": "queued",
            "created_at": created_at, "updated_at": created_at,
            "session_id": body["session_id"], "model": body.get("model", self._model_name),
        }

        def _new_worker(worker_deadline: float) -> _ProtectedNewAdmission:
            return _prepare_and_reserve_protected(
                self, recovery_owner, body, recovery_admission, idempotency_key,
                idempotency_fingerprint, run_id, initial_status, worker_deadline,
            )

        try:
            work = self._recovery_workers.submit(_new_worker, deadline=deadline)
            wrapped = asyncio.wrap_future(work.future)
            wrapped.add_done_callback(_collect_async_result)
            protected_new = await asyncio.shield(wrapped)
        except (RecoveryHttpRefused, RecoveryDeadlineExceeded, RecoveryRefused,
                sqlite3.DatabaseError, OSError, AttributeError):
            return _json_error(
                _openai_error, "Protected admission unavailable",
                code="recovery_runtime_unavailable",
                status=503,
            )
        db = protected_new.db
        protected_store = protected_new.store
        protected_scope = protected_new.scope
        prepared_runtime = protected_new.runtime
        provider_capture = protected_new.provider_capture
        if protected_new.result.outcome != "created":
            if protected_new.result.outcome == "replayed":
                return _accepted_response(
                    protected_new.result.member.run_id, protected_new.replay_status,
                    gateway_session_key, replayed=True,
                )
            return _json_error(
                _openai_error, "Protected admission refused",
                code=protected_new.result.reason or "recovery_conflict", status=409,
            )
    # Same precedence as /v1/responses: body session_id > response chain > X-Hermes-Session-Key
    # conversation > run_id (which would otherwise re-key every affinity surface per run).
    # An explicit or chained session owns its routing key and is never rebound to the header.
    _declared_selected = not session_id and bool(gateway_session_key)
    if recovery_admission is None:
        from hermes_recovery_dispatch import (
            claim_exact_ordinary, resolve_declared_ordinary, selected_state_db_path,
        )
        from hermes_state_recovery import RecoveryRefused

        try:
            async with self._ordinary_claim_lock:
                path = selected_state_db_path(self._session_db)
                selected_session_id = session_id or (
                    await asyncio.to_thread(resolve_declared_ordinary, path, gateway_session_key)
                    if _declared_selected else None)
                original_session_id = session_id or selected_session_id or run_id
                claimed = await asyncio.to_thread(
                    claim_exact_ordinary, path, (original_session_id,))
        except RecoveryRefused:
            return _json_error(_openai_error, "Session authority unavailable",
                               code="protected_session_refused", status=409)
        session_id = claimed.resolved_ids[0]
        selected_session_id = session_id if selected_session_id else None
    else:
        selected_session_id = body["session_id"]
        session_id = selected_session_id
    self._run_owners[run_id] = self._run_idempotency_scope(request)
    if recovery_owner is not None:
        if protected_scope is None:
            self._run_owners.pop(run_id, None)
            return _json_error(_openai_error, "Protected scope unavailable",
                               code="recovery_store_unavailable", status=503)
        self._protected_physical_owners[run_id] = (
            recovery_owner, protected_scope.store_id,
        )
    # History loads for the session the request actually selected — including one resolved from
    # a declared X-Hermes-Session-Key, whose persisted delivery rows must reach the next
    # same-key run's context (#98619).  previous_response_id continuations keep their
    # ResponseStore snapshot as history (they cannot consume a SessionDB delivery row and are
    # accordingly denied wake capability in _run_agent_sync); the fresh run_id fallback has
    # nothing persisted to load yet.  Wake authority is fixed here, before the load can
    # overwrite ``conversation_history``: a caller-supplied history is authoritative for this
    # turn, never consumes the SessionDB delivery row, and is denied on the same contract.
    session_history_delivery = not previous_response_id and not conversation_history
    if not conversation_history and selected_session_id and not previous_response_id:
        if recovery_admission is None:
            conversation_history = await self._conversation_history_for_session(str(selected_session_id))
        else:
            assert protected_new is not None
            conversation_history = protected_new.history
    # There is no await between this final capacity check and the observer's
    # creation. Session resolution above can yield to another admission.
    if diagnostic_requested:
        _tool_diag.sweep(self)
        error = _tool_diag.capacity_error(self, _openai_error=_openai_error)
        if error is not None:
            self._run_owners.pop(run_id, None)
            return error
    if recovery_admission is not None:
        from hermes_state_recovery import RecoveryRefused

        if (protected_new is None or provider_capture is None
                or protected_store is None or protected_scope is None):
            _forget_run(self, run_id, self._run_owners)
            return _json_error(_openai_error, "Protected admission unavailable",
                               code="recovery_runtime_unavailable", status=503)
        try:
            provider_capture.require_selected()
            provider_ref = weakref.ref(provider_capture.provider)
            prior_provider = self._protected_provider_identities.get(protected_scope)
            if prior_provider is not None:
                if (prior_provider[0]() is not provider_capture.provider
                        or prior_provider[1] != provider_capture.admission.canonical_bytes()):
                    raise RecoveryRefused("provider_selection_changed")
            elif recovery_admission.generation != 0 or len(self._protected_provider_identities) >= 1024:
                raise RecoveryRefused("provider_identity_unavailable")
        except (RecoveryRefused, TypeError) as exc:
            try:
                await _settle_undispatched_protected(
                    protected_new, run_id, initial_status,
                    reason="unsupported_configuration",
                )
            except Exception:
                logger.exception("[api_server] committed protected admission could not settle")
            self._run_owners.pop(run_id, None)
            self._protected_physical_owners.pop(run_id, None)
            return _json_error(_openai_error, "Protected provider admission refused",
                               code=exc.code if isinstance(exc, RecoveryRefused)
                               else "provider_identity_unavailable", status=503)
    tool_observer = (_tool_diag.create(
        self, run_id, _api_server._api_request_profile.get() or "default",
        self._run_owners[run_id]) if diagnostic_requested else None)
    q = self._run_streams[run_id] = asyncio.Queue()
    created_at = self._run_streams_created[run_id] = time.time()
    self._run_approval_sessions[run_id] = run_id  # approval session key (see _RunLaunch)
    initial_status = self._set_run_status(
        run_id, "queued", created_at=created_at, session_id=session_id, model=body.get("model", self._model_name))
    if recovery_admission is not None:
        if (protected_new is None or protected_store is None or protected_scope is None
                or provider_capture is None):
            _forget_run(self, run_id, self._run_streams, self._run_streams_created,
                        self._run_approval_sessions, self._run_statuses, self._run_owners)
            return _json_error(_openai_error, "Protected admission unavailable",
                               code="recovery_runtime_unavailable", status=503)
        result = protected_new.result
        recovery_handoff = result.handoff
        from agent.recovery_context import issue_producer_permit, issue_write_permit
        from agent.recovery_producers import ProducerRegistry
        setup: dict[str, Any] = {}

        def _register_committed() -> None:
            setup["permit"] = issue_producer_permit(protected_store, recovery_handoff)
            registry = ProducerRegistry(
                protected_store, protected_scope, run_id, recovery_admission.generation,
                setup["permit"],
            )
            setup["registry"] = registry
            setattr(registry, "provider_capture", provider_capture)
            setup["barrier"] = registry.enter(registry.permit, "callback")
            setup["write_permit"] = issue_write_permit(
                registry.permit, protected_store, protected_scope, run_id,
                recovery_admission.generation,
            )

        try:
            # This is mandatory post-commit ownership work. The HTTP waiter may
            # expire, but the retained admission task must join the actual
            # registration thread before dispatch or incomplete settlement.
            await asyncio.shield(asyncio.to_thread(_register_committed))
            recovery_registry = setup["registry"]
            recovery_status_barrier = setup["barrier"]
            recovery_write_permit = setup["write_permit"]
            self._protected_provider_identities.setdefault(
                protected_scope, (provider_ref, provider_capture.admission.canonical_bytes()))
            self._protected_run_ids.add(run_id)
            self._protected_run_stores[run_id] = protected_store
            self._protected_run_registries[run_id] = recovery_registry
        except Exception:
            try:
                await _settle_undispatched_protected(
                    protected_new, run_id, initial_status,
                    reason="unclosed_producer", permit=setup.get("permit"),
                    registry=setup.get("registry"), barrier=setup.get("barrier"),
                )
            except Exception:
                logger.exception("[api_server] committed protected admission could not settle")
            _forget_run(self, run_id, self._run_streams, self._run_streams_created,
                        self._run_approval_sessions, self._run_statuses, self._run_owners)
            self._protected_physical_owners.pop(run_id, None)
            self._protected_run_ids.discard(run_id)
            self._protected_run_stores.pop(run_id, None)
            self._protected_run_registries.pop(run_id, None)
            return _json_error(_openai_error, "Protected dispatch unavailable",
                               code="recovery_runtime_unavailable", status=503)
    elif idempotency_key:
        outcome, record = self._run_idempotency_store.reserve(
            idempotency_scope, idempotency_key, idempotency_fingerprint, run_id, initial_status,
            owner_pid=self._run_owner_pid, owner_started=self._run_owner_started,
            retention_until=_room_retention_until(request))
        if outcome != "created":
            self._run_tool_diagnostics.pop(run_id, None)
            _forget_run(
                self, run_id, self._run_streams, self._run_streams_created, self._run_approval_sessions,
                self._run_statuses, self._run_owners)
            return _replay_or_conflict(self, request, outcome, record, gateway_session_key, _openai_error)
        self._run_idempotency_ids.add(run_id)
    launch = _RunLaunch(
        self, run_id, q, session_id, gateway_session_key, _declared_selected, user_message,
        conversation_history, session_history_delivery,
        agent_kwargs=dict(
            ephemeral_system_prompt=instructions, session_id=session_id, gateway_session_key=gateway_session_key,
            route=route, room_dispatch=room_dispatch, room_execution_policy=room_execution_policy,
            **{k: agent_overrides.get(k) for k in ("requested_model", "requested_provider", "model_options")}),
        request_profile=_api_server._api_request_profile.get(),
        browser_control_principal=_api_server._api_request_browser_control_principal.get(),
        browser_control_transport_family=_api_server._api_request_browser_control_transport_family.get(),
        turn_author=turn_author,
        tool_observer=tool_observer,
        recovery_handoff=recovery_handoff,
        recovery_provider_capture=provider_capture,
        recovery_runtime=prepared_runtime,
        recovery_registry=recovery_registry,
        recovery_write_permit=recovery_write_permit,
        recovery_status_barrier=recovery_status_barrier,
        recovery_execution_settled=threading.Event() if recovery_registry is not None else None,
        recovery_coroutine_settled=asyncio.Event() if recovery_registry is not None else None)
    observer = None
    if recovery_registry is not None:
        assert protected_new is not None
        try:
            observer_coro = _finalize_protected_producers(self, launch)
            try:
                observer = asyncio.create_task(observer_coro)
            except BaseException:
                observer_coro.close()
                raise
            run_coro = _execute_run(self, launch, _api_server=_api_server)
            try:
                task = asyncio.create_task(run_coro)
            except BaseException:
                run_coro.close()
                raise
        except Exception:
            if observer is not None:
                observer.cancel()
            try:
                await _settle_undispatched_protected(
                    protected_new, run_id, initial_status, reason="unclosed_producer",
                    registry=recovery_registry, barrier=recovery_status_barrier,
                )
            except Exception:
                logger.exception("[api_server] committed protected dispatch could not settle")
            _forget_run(self, run_id, self._run_streams, self._run_streams_created,
                        self._run_approval_sessions, self._run_statuses, self._run_owners)
            self._protected_physical_owners.pop(run_id, None)
            self._protected_run_ids.discard(run_id)
            self._protected_run_stores.pop(run_id, None)
            self._protected_run_registries.pop(run_id, None)
            return _json_error(_openai_error, "Protected dispatch unavailable",
                               code="recovery_runtime_unavailable", status=503)
        self._active_run_tasks[run_id] = task
        self._background_tasks.add(observer)
        observer.add_done_callback(self._background_tasks.discard)
    else:
        task = self._active_run_tasks[run_id] = asyncio.create_task(
            _execute_run(self, launch, _api_server=_api_server))
    self._activate_admitted_request()
    with suppress(TypeError):
        self._background_tasks.add(task)  # tracked for shutdown drain
    if hasattr(task, "add_done_callback"):
        task.add_done_callback(self._background_tasks.discard)
    return _accepted_response(run_id, "started", gateway_session_key, replayed=False)


def _run_agent_sync(self, run: _RunLaunch, agent, approval_notify, *, _api_server):
    """Executor-thread body of one run; returns ``(result, usage)``."""
    observer = run.tool_observer
    try:
        return _run_agent_sync_body(self, run, agent, approval_notify, _api_server=_api_server)
    except BaseException:
        if observer is not None:
            observer.mark_incomplete("unclosed_producer")
        raise
    finally:
        # Own the producer from the first import through profile-scope entry,
        # run cleanup, and usage extraction. The awaiting coroutine cannot
        # certify this closure after its Future is cancelled.
        if observer is not None:
            observer.close_producer()


def _run_agent_sync_body(self, run: _RunLaunch, agent, approval_notify, *, _api_server):
    from gateway.session_context import clear_session_vars
    from gateway.hosted_room_execution_policy import (
        RoomExecutionPolicy, bind_room_execution_policy, reset_room_execution_policy)
    # No eager slash-worker pre-warm: slash.exec spawns one on demand (its error path already relies on that
    # respawn to recover from a dead worker). Each worker child runs its own MCP discovery (#61891), so
    # pre-warming one per session forks the full stdio MCP fleet — ~20 OS processes per retained session on
    # a config with a few stdio servers — even for sessions that never run a worker-routed command. Sessions
    # held by a live transport are never reaped, so with the desktop app open for days those fleets
    # accumulate until the OS refuses new process spawns.
    from tools.approval import register_gateway_notify, unregister_gateway_notify
    from tools.approval_context import reset_current_session_key, set_current_session_key
    session_id = run.session_id
    effective_task_id = session_id or run.run_id
    # (token, reset) pairs unwound in the finally block; bound only once each step succeeds.
    resets: list[tuple[Any, Callable]] = []
    observer = run.tool_observer
    observer_token = None
    from gateway.run import _profile_runtime_scope
    profile_scope = (
        _profile_runtime_scope(run.recovery_runtime.home)
        if run.recovery_runtime is not None else self._profile_scope(run.request_profile)
    )
    with profile_scope:
        try:
            if observer is not None:
                from agent.tool_diagnostic import current_tool_send_observer
                agent._tool_send_observer = observer
                observer_token = current_tool_send_observer.set(observer)
                from agent.tool_diagnostic_transport import bind_agent_tool_scope
                bind_agent_tool_scope(agent, observer)
            # Contextvars, not process env: concurrent runs must not share identity.
            resets.append((set_current_session_key(run.approval_session_key), reset_current_session_key))
            # chat_id carries the raw session id like _run_agent() does; without it
            # tools.async_delegation sees no HERMES_SESSION_CHAT_ID and forces delegations sync.
            session_tokens = self._bind_api_server_session(
                chat_id=session_id or "", session_key=run.approval_session_key, session_id=session_id or "",
                profile=run.request_profile or "",
                browser_control_principal=run.browser_control_principal,
                browser_control_transport_family=run.browser_control_transport_family,
                # #98619 audited opt-in: the /v1/runs session id is wake-capable only when its
                # own continuation path reloads session history — an explicit body/chained
                # session id or a declared X-Hermes-Session-Key conversation (both load
                # SessionDB in _handle_runs), or the run_id fallback the client can post back
                # as body.session_id.  A previous_response_id continuation consumes its
                # ResponseStore snapshot instead and can never see a SessionDB delivery row,
                # so it stays default-denied until a merge contract exists for that chain;
                # likewise a caller-supplied conversation_history is authoritative for the
                # turn and never reads the delivery row, so it is denied the same way.
                session_history_delivery="1" if run.session_history_delivery else "")
            if session_tokens:
                resets.append((session_tokens, clear_session_vars))
            if run.agent_kwargs["room_dispatch"] is not None:
                policy = RoomExecutionPolicy.from_mapping(run.agent_kwargs["room_execution_policy"] or {})
                resets.append((bind_room_execution_policy(policy), reset_room_execution_policy))
            register_gateway_notify(run.approval_session_key, approval_notify)
            # /v1/runs owns its agent lifecycle (no TurnRunner): record process ownership
            # so stop/cancel reaps only the background processes this run created.
            _api_server._publish_turn_process_ownership(agent, effective_task_id)
            # Passed only when set: a human turn keeps today's call shape.
            author_kwargs = {"turn_author": run.turn_author} if run.turn_author is not None else {}
            if run.recovery_write_permit is None:
                r = agent.run_conversation(
                    user_message=run.user_message, conversation_history=run.conversation_history,
                    task_id=effective_task_id, **author_kwargs)
            else:
                from agent.recovery_context import bind_write_permit
                with bind_write_permit(run.recovery_write_permit):
                    r = agent.run_conversation(
                        user_message=run.user_message, conversation_history=run.conversation_history,
                        task_id=effective_task_id, **author_kwargs)
        finally:
            try:
                # Clear ownership now so a later stop can't reap work this run left running.
                _api_server._clear_turn_process_ownership(agent)
                if run.declared_selected:
                    self._bind_declared_conversation(
                        getattr(agent, "session_id", None) or session_id, run.gateway_session_key)
                unregister_gateway_notify(run.approval_session_key)
            finally:
                for token, reset in resets:
                    with suppress(Exception):
                        reset(token)
                if observer_token is not None:
                    current_tool_send_observer.reset(observer_token)
        return r, {key: getattr(agent, attr, 0) or 0 for key, attr in _USAGE_FIELDS}


def _approval_run_event(run_id: str, approval_data: Dict[str, Any], *, _api_server) -> Dict[str, Any]:
    """Build one egress-safe prompt from the live approval queue."""
    event = dict(approval_data)
    if "command" in event:
        from gateway.run import _redact_approval_command
        event["command"] = _redact_approval_command(event.get("command"))
    event.update(_run_event(run_id, "approval.request", choices=_api_server._approval_event_choices(
        smart_denied=bool(event.get("smart_denied")),
        allow_session=event.get("allow_session") is not False,
        allow_permanent=event.get("allow_permanent") is not False)))
    return event


def _project_run_approval(self, run_id: str, *, _api_server) -> None:
    """Make pollable status name only a request still waiting in this run's queue."""
    current = self._run_statuses.get(run_id)
    if (current is None or run_id not in self._run_approval_sessions
            or current.get("status") in TERMINAL_STATUSES | {"stopping"}
            or run_id in self._stopping_run_ids):
        return
    from tools.approval import list_gateway_approvals
    pending = list_gateway_approvals(self._run_approval_sessions[run_id])
    if pending:
        current_id = (current.get("approval") or {}).get("request_id")
        selected = next((item for item in pending if item.get("request_id") == current_id), None)
        if selected is None:
            selected = pending[0]
        if current.get("status") != "waiting_for_approval" or selected.get("request_id") != current_id:
            self._set_run_status(
                run_id, "waiting_for_approval", last_event="approval.request",
                approval=_approval_run_event(run_id, selected, _api_server=_api_server))
    elif current.get("status") == "waiting_for_approval":
        self._set_run_status(run_id, "running")


def _make_approval_notify(self, run: _RunLaunch, *, _api_server) -> Callable[[Dict[str, Any]], None]:
    """Present a request while pending and withdraw it when the core settles its wait."""
    run_id, q, loop = run.run_id, run.queue, asyncio.get_running_loop()

    def _approval_notify(approval_data: Dict[str, Any]) -> None:
        request_id = approval_data.get("request_id")

        def _settled(_reason: str) -> None:
            if run.recovery_registry is not None and run.recovery_coroutine_settled.is_set():
                return
            _schedule_run_callback(
                self, run_id, loop,
                lambda: _project_run_approval(self, run_id, _api_server=_api_server))

        from tools.approval import register_gateway_settle
        registered = bool(request_id) and register_gateway_settle(
            run.approval_session_key, request_id, _settled)

        def _publish() -> None:
            _project_run_approval(self, run_id, _api_server=_api_server)
            from tools.approval import list_gateway_approvals
            if (registered and self._run_statuses.get(run_id, {}).get("status") == "waiting_for_approval"
                    and any(item.get("request_id") == request_id for item in
                            list_gateway_approvals(run.approval_session_key))):
                q.put_nowait(_approval_run_event(run_id, approval_data, _api_server=_api_server))

        _schedule_run_callback(self, run_id, loop, _publish)

    return _approval_notify


async def _finalize_protected_producers(self, run: _RunLaunch) -> None:
    """Retain closure authority after a cancelled HTTP/executor waiter."""
    registry = run.recovery_registry
    try:
        await run.recovery_coroutine_settled.wait()
        await asyncio.to_thread(run.recovery_execution_settled.wait)
        await asyncio.to_thread(
            registry.wait_until_quiescent, excluding=run.recovery_status_barrier)
        await _await_protected_status(self, run.run_id)
        await asyncio.to_thread(run.recovery_status_barrier.run, lambda: None)
        self._protected_run_registries.pop(run.run_id, None)
    except BaseException:
        logger.exception("[api_server] protected producer finalization failed for %s", run.run_id)
        raise


async def _enter_protected_executor_lease(registry):
    """Register an executor off-loop and settle a late registration on cancel."""
    opening = asyncio.create_task(asyncio.to_thread(registry.enter, registry.permit, "executor"))
    try:
        return await asyncio.shield(opening)
    except asyncio.CancelledError:
        # The thread may have committed a queued lease. Do not lose it merely
        # because the awaiting run task was cancelled during registration.
        try:
            lease = await asyncio.shield(opening)
            await asyncio.to_thread(lease.cancel_before_start)
        except Exception:
            logger.exception("[api_server] cancelled protected lease could not settle")
        raise


async def _execute_run(self, run: _RunLaunch, *, _api_server) -> None:
    """Drive one admitted run, publish its terminal event/status, release live state."""
    _redact_api_error_text = _api_server._redact_api_error_text
    run_id, loop = run.run_id, asyncio.get_running_loop()

    def _text_cb(delta: Optional[str]) -> None:
        if delta is None or run_id not in self._run_streams:
            return
        _schedule_run_callback(
            self, run_id, loop,
            lambda: run.put_event(_run_event(run_id, "message.delta", delta=delta)))

    async def _finish(status: str, extra: Optional[dict] = None, **fields: Any) -> None:
        """Terminal status, then best-effort ``run.<status>`` event; key order is wire shape."""
        extra = extra or {}
        self._set_run_status(run_id, status, **fields, last_event=f"run.{status}", **extra)
        await _await_protected_status(self, run_id)
        with suppress(Exception):
            run.put_event(_run_event(run_id, f"run.{status}", **fields, **extra))

    producer_dispatched = False
    try:
        self._set_run_status(run_id, "running")
        await _await_protected_status(self, run_id)
        if run_id in self._stopping_run_ids:
            await _finish("cancelled")
            return
        from agent.tool_diagnostic import current_tool_send_observer
        observer_token = current_tool_send_observer.set(run.tool_observer) if run.tool_observer else None
        try:
            from gateway.run import _profile_runtime_scope
            profile_scope = (
                _profile_runtime_scope(run.recovery_runtime.home)
                if run.recovery_runtime is not None else self._profile_scope(run.request_profile)
            )
            with profile_scope:
                if run.recovery_write_permit is None:
                    agent = self._create_agent(
                        stream_delta_callback=_text_cb,
                        tool_progress_callback=self._make_run_event_callback(run_id, loop),
                        **run.agent_kwargs)
                else:
                    from agent.recovery_context import bind_write_permit
                    from agent.recovery_producers import bind_registry
                    registry = run.recovery_registry
                    construction_lease = await _enter_protected_executor_lease(registry)
                    def _construct_agent():
                        token = _api_server._recovery_construction_lease.set(construction_lease)
                        try:
                            from agent.recovery_producers import bind_protected_constructor
                            with bind_registry(registry), bind_write_permit(run.recovery_write_permit):
                                def _build():
                                    with bind_protected_constructor(run.recovery_runtime):
                                        return self._create_agent(
                                            stream_delta_callback=_text_cb,
                                            tool_progress_callback=self._make_run_event_callback(run_id, loop),
                                            protected_runtime=run.recovery_runtime,
                                            **run.agent_kwargs)
                                return construction_lease.run(_build)
                        finally:
                            _api_server._recovery_construction_lease.reset(token)
                    try:
                        agent = await asyncio.to_thread(_construct_agent)
                    except BaseException:
                        # Cancellation can detach the awaiter while the worker is
                        # constructing; its durable lease remains open until it exits.
                        from hermes_state_recovery import RecoveryRefused
                        try:
                            await asyncio.to_thread(construction_lease.cancel_before_start)
                        except RecoveryRefused:
                            pass
                        raise
        finally:
            if observer_token is not None:
                current_tool_send_observer.reset(observer_token)
        self._active_run_agents[run_id] = agent
        if run.recovery_registry is not None:
            registry = run.recovery_registry
            agent._recovery_registry = registry
            agent._recovery_write_permit = run.recovery_write_permit
        approval_notify = _make_approval_notify(self, run, _api_server=_api_server)
        if run.recovery_registry is None:
            executor_future = loop.run_in_executor(
                None, lambda: _run_agent_sync(self, run, agent, approval_notify, _api_server=_api_server))
        else:
            registry = run.recovery_registry
            lease = await _enter_protected_executor_lease(registry)
            def _protected_worker():
                try:
                    return lease.run(
                        lambda: _run_agent_sync(self, run, agent, approval_notify, _api_server=_api_server))
                finally:
                    run.recovery_execution_settled.set()
            try:
                executor_future = loop.run_in_executor(None, _protected_worker)
            except BaseException:
                await asyncio.to_thread(lease.cancel_before_start)
                run.recovery_execution_settled.set()
                raise
        producer_dispatched = True
        # A cancelled protected waiter cannot cancel the underlying queued
        # worker: its registered lease must settle from the actual thread.
        result, usage = await (asyncio.shield(executor_future)
                               if run.recovery_registry is not None else executor_future)
        if not isinstance(result, dict):
            result = {}
        if run_id in self._stopping_run_ids and result.get("interrupted") is True:
            await _finish("cancelled")
        elif result.get("failed"):
            # Non-retryable client errors (401/400) return failed=True rather than raising.
            await _finish("failed", error=_redact_api_error_text(result.get("error") or "agent run failed"))
        else:
            # Undelivered steer text rides on the terminal event/status for client replay.
            extra = {"pending_steer": result["pending_steer"]} if result.get("pending_steer") else {}
            await _finish("completed", extra, output=result.get("final_response", ""), usage=usage)
    except asyncio.CancelledError:
        await _finish("cancelled")
        raise
    except _api_server._ProviderAuthResolutionError as exc:
        # Same controlled provider-auth message the _run_agent() endpoints give.
        logger.warning("Provider authentication failed for run=%s: %s", run_id, exc)
        await _finish("failed", error=f"⚠️ Provider authentication failed: {exc}")
    except Exception as exc:
        logger.exception("[api_server] run %s failed", run_id)
        await _finish("failed", error=_redact_api_error_text(exc))
    finally:
        if run.recovery_registry is not None:
            if not producer_dispatched:
                run.recovery_execution_settled.set()
            try:
                await asyncio.to_thread(run.recovery_registry.request_close)
            finally:
                run.recovery_coroutine_settled.set()
        if run.tool_observer is not None and not producer_dispatched:
            run.tool_observer.mark_incomplete("unclosed_producer")
            run.tool_observer.close_producer()
        # On cancellation (/stop) the executor thread may still block on an approval
        # Event; unregistering releases it. Idempotent on normal completion.
        _unregister_approval_notify(run.approval_session_key)
        with suppress(Exception):
            run.put_event(None)  # sentinel: close the SSE stream
        _retire_live_run(self, run_id)


def _unregister_approval_notify(approval_session_key: Optional[str]) -> None:
    """Best-effort release of a run's approval waiter (no-op without a key)."""
    with suppress(Exception):
        from tools.approval import unregister_gateway_notify
        if approval_session_key:
            unregister_gateway_notify(approval_session_key)


def _release_run_owner_if_forgotten(self, run_id: str) -> None:
    """Drop the owner stamp only once nothing keyed by *run_id* survives: ownership must
    outlive every surface it protects (retired on different clocks); ownerless = fail-closed."""
    live = (self._run_statuses, self._active_run_agents, self._active_run_tasks, self._run_streams,
            self._run_approval_sessions, self._run_tool_diagnostics,
            self._run_tool_diagnostic_tombstones)
    if not any(run_id in table for table in live):
        self._run_owners.pop(run_id, None)
        self._protected_physical_owners.pop(run_id, None)


def _request_owns_run(self, request: "web.Request", run_id: str) -> bool:
    scope = self._run_idempotency_scope(request)
    owner = self._run_owners.get(run_id)
    if owner is not None:
        protected_owner = self._protected_physical_owners.get(run_id)
        if protected_owner is not None:
            from gateway.platforms import api_server
            from gateway.platforms.api_server_recovery import (
                RecoveryHttpRefused, capture_owner_context,
            )
            try:
                captured = capture_owner_context(
                    self, request, selected_profile=api_server._api_request_profile.get()
                )
            except RecoveryHttpRefused:
                return False
            return owner == scope and protected_owner[0] == captured
        return owner == scope
    # No in-memory owner: only a durable record under the caller's scope admits it.
    # Under multiplex_profiles every profile holds a valid key, so ownerless = allow-all.
    # Run state that exists without an owner stamp is an unanswered authorization question, not a run anyone
    # may control — under gateway.multiplex_profiles every served profile holds a valid key, so admitting it
    # would make the boundary allow-all (#93689).
    if self._run_idempotency_store.owns_run(scope, run_id):
        return True
    return False


async def _cold_protected_owner(self, request: "web.Request", run_id: str) -> bool:
    """Resolve an uncached protected owner in the same bounded pool as recovery GET."""
    from gateway.platforms.api_server_recovery import (
        RecoveryHttpRefused, _collect_async_result, capture_owner_context,
        read_protected_run_status,
    )
    from gateway.platforms import api_server
    from hermes_state_recovery import RecoveryRefused
    from hermes_state_recovery_deadline import RecoveryDeadlineExceeded
    try:
        captured = capture_owner_context(
            self, request, selected_profile=api_server._api_request_profile.get()
        )
    except RecoveryHttpRefused:
        return False
    try:
        deadline = time.monotonic() + _COLD_PROTECTED_STATUS_SECONDS
        work = self._recovery_workers.submit(
            lambda _deadline: read_protected_run_status(captured, run_id),
            deadline=deadline,
        )
        wrapped = asyncio.wrap_future(work.future)
        wrapped.add_done_callback(_collect_async_result)
        protected = await asyncio.wait_for(
            asyncio.shield(wrapped), timeout=max(0.0, deadline - time.monotonic()),
        )
    except (RecoveryDeadlineExceeded, asyncio.TimeoutError) as exc:
        raise RecoveryHttpRefused(504, "recovery_deadline_exceeded") from exc
    except (RecoveryRefused, sqlite3.DatabaseError, OSError, AttributeError) as exc:
        raise RecoveryHttpRefused(503, "recovery_store_unavailable") from exc
    if protected is None:
        return False
    scope = self._run_idempotency_scope(request)
    self._run_statuses[run_id] = dict(protected.status)
    self._run_owners[run_id] = scope
    self._protected_physical_owners[run_id] = (captured, protected.store_id)
    return True


async def _request_owns_run_async(self, request: "web.Request", run_id: str) -> bool:
    if await asyncio.to_thread(self._request_owns_run, request, run_id):
        return True
    if run_id in self._run_owners:
        return False
    return await _cold_protected_owner(self, request, run_id)


def _load_owned_run(self, request, *, _api_server, permission: Optional[str], active_fallback: bool):
    """Authenticate (*permission* -> room-grant aware; ``None`` -> API key only) and resolve
    ``(run_id, status, agent, task, error)``; *active_fallback* reports a live in-process run
    without pollable status as ``running`` instead of 404."""
    auth_err = self._check_run_auth(request, permission=permission) if permission else self._check_auth(request)
    if auth_err:
        return None, None, None, None, auth_err
    _openai_error = _api_server._openai_error
    run_id = request.match_info["run_id"]
    if not self._request_owns_run(request, run_id):
        return run_id, None, None, None, _run_not_found(_openai_error, run_id)
    agent = self._active_run_agents.get(run_id)
    task = self._active_run_tasks.get(run_id)
    status = self._durable_run_status(request, run_id)
    if (status is None and active_fallback and run_id not in self._protected_run_ids
            and (agent is not None or task is not None)):
        status = self._set_run_status(run_id, "running")
    if status is None:
        return run_id, None, agent, task, _run_not_found(_openai_error, run_id)
    return run_id, status, agent, task, None


async def _load_owned_run_async(
    self, request, *, _api_server, permission: Optional[str], active_fallback: bool,
):
    result = await asyncio.to_thread(
        _load_owned_run, self, request, _api_server=_api_server,
        permission=permission, active_fallback=active_fallback,
    )
    run_id, _status, _agent, _task, error = result
    if error is None or error.status != 404 or run_id in self._run_owners:
        return result
    from gateway.platforms.api_server_recovery import RecoveryHttpRefused
    try:
        found = await _cold_protected_owner(self, request, run_id)
    except RecoveryHttpRefused as exc:
        refused = _json_error(
            _api_server._openai_error, "Protected status unavailable",
            code=exc.code, status=exc.status,
        )
        return run_id, None, None, None, refused
    if not found:
        return result
    return await asyncio.to_thread(
        _load_owned_run, self, request, _api_server=_api_server,
        permission=permission, active_fallback=active_fallback,
    )


async def _handle_get_run(self, request: "web.Request", *, _api_server) -> "web.Response":
    """GET /v1/runs/{run_id} — return pollable run status for external UIs."""
    run_id, status, _, _, err = await _load_owned_run_async(
        self, request, _api_server=_api_server, permission="status", active_fallback=True)
    if err is None and run_id in self._protected_run_ids:
        try:
            await _await_protected_status(self, run_id)
        except Exception:
            return _json_error(_api_server._openai_error, "Protected status unavailable",
                               code="recovery_status_unavailable", status=503)
    return err or web.json_response(status)


async def _handle_run_events(self, request: "web.Request", *, _api_server) -> "web.StreamResponse":
    """GET /v1/runs/{run_id}/events — stream structured agent lifecycle events."""
    auth_err = self._check_auth(request)
    if auth_err:
        return auth_err
    run_id = request.match_info["run_id"]
    from gateway.platforms.api_server_recovery import RecoveryHttpRefused
    try:
        owned = await _request_owns_run_async(self, request, run_id)
    except RecoveryHttpRefused as exc:
        return _json_error(_api_server._openai_error, "Protected status unavailable",
                           code=exc.code, status=exc.status)
    if not owned:
        return _run_not_found(_api_server._openai_error, run_id)
    # Allow subscribing slightly before the run is registered (race window).
    # Confirm the force-kill actually reaped the process before we clear its PID file / scoped locks.
    # SIGKILL can fail to take (e.g. an uninterruptible-sleep or zombie-reaping parent), and if we blindly
    # clear the metadata and start a fresh instance we end up with two live gateways fighting over the same
    # token — the duplicate-gateway failure in #19471.
    for _ in range(20):
        if run_id in self._run_streams:
            break
        await asyncio.sleep(0.05)
    else:
        return _run_not_found(_api_server._openai_error, run_id)
    q = self._run_streams[run_id]
    self._run_stream_subscribers.add(run_id)
    response = web.StreamResponse(status=200, headers={
        "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    await response.prepare(request)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                await response.write(b": keepalive\n\n")
                continue
            if event is None:  # run finished
                await response.write(b": stream closed\n\n")
                break
            await response.write(_api_server._sse_frame(event))
    except Exception as exc:
        logger.debug("[api_server] SSE stream error for run %s: %s", run_id, exc)
    finally:
        self._run_stream_subscribers.discard(run_id)
        _drop_run_transport(self, run_id)
    return response


def _mark_run_event(self, run_id: str, name: str, **fields: Any) -> None:
    """Record a control-plane event on the run status and (best effort) its SSE stream."""
    current = self._run_statuses.get(run_id)
    if current is not None and current.get("status") not in TERMINAL_STATUSES | {"stopping"}:
        self._set_run_status(run_id, current["status"], last_event=name)
    q = self._run_streams.get(run_id)
    if q is not None:
        with suppress(Exception):
            q.put_nowait(_run_event(run_id, name, **fields))


_APPROVAL_CHOICE_ALIASES = {"approve": "once", "approved": "once", "allow": "once"}


async def _handle_run_approval(self, request: "web.Request", *, _api_server) -> "web.Response":
    """POST /v1/runs/{run_id}/approval — resolve a pending run approval."""
    _openai_error = _api_server._openai_error
    run_id, _, _, _, err = await _load_owned_run_async(
        self, request, _api_server=_api_server, permission="approve", active_fallback=False)
    if err is not None:
        return err
    try:
        body = await request.json()
    except Exception:
        return _json_error(_openai_error, "Invalid JSON", status=400)
    raw_choice = str(body.get("choice", "")).strip().lower()
    choice = _APPROVAL_CHOICE_ALIASES.get(raw_choice, raw_choice)
    room_scoped = bool(self._room_grant_token(request))
    raw_request_id = body.get("request_id")
    request_id = raw_request_id.strip() if isinstance(raw_request_id, str) else ""
    # Room grants may resolve exactly one request and never widen to session/always.
    allowed = {"once", "deny"} if room_scoped else {"once", "session", "always", "deny"}
    resolve_all = any(_api_server._coerce_request_bool(body.get(k), default=False) for k in ("all", "resolve_all"))
    approval_session_key = self._run_approval_sessions.get(run_id)
    for failed, message, code, status in (
        (raw_request_id is not None and (not request_id or len(request_id) > 256),
         "Approval request_id is invalid.", "invalid_approval_request", 400),
        (choice not in allowed,
         "Invalid approval choice; expected one of: " + ", ".join(sorted(allowed)),
         "invalid_approval_choice", 400),
        (room_scoped and resolve_all,
         "Room approvals can resolve only one exact request", "invalid_approval_scope", 400),
        (room_scoped and not request_id,
         "Room approvals require the exact request_id.", "approval_request_required", 400),
        (not approval_session_key,
         f"Run has no active approval session: {run_id}", "approval_not_active", 409)):
        if failed:
            return _json_error(_openai_error, message, code=code, status=status)
    try:
        from tools.approval import resolve_gateway_approval
        resolved = resolve_gateway_approval(
            approval_session_key, choice, resolve_all=resolve_all, request_id=request_id or None)
    except Exception as exc:
        logger.exception("[api_server] approval resolution failed for run %s", run_id)
        return _json_error(_openai_error, str(exc), status=500)
    if resolved <= 0:
        _project_run_approval(self, run_id, _api_server=_api_server)
        return _json_error(
            _openai_error, f"Run has no pending approval: {run_id}", code="approval_not_pending", status=409)
    request_id_field = {"request_id": request_id} if request_id else {}
    _project_run_approval(self, run_id, _api_server=_api_server)
    _mark_run_event(self, run_id, "approval.responded", choice=choice, **request_id_field, resolved=resolved)
    return web.json_response({
        "object": "hermes.run.approval_response", "run_id": run_id, "choice": choice, **request_id_field,
        "resolved": resolved})


async def _handle_steer_run(self, request: "web.Request", *, _api_server) -> "web.Response":
    """POST /v1/runs/{run_id}/steer — inject guidance into a running agent."""
    _openai_error = _api_server._openai_error
    run_id, status, agent, _, err = await _load_owned_run_async(
        self, request, _api_server=_api_server, permission=None, active_fallback=False)
    if err is not None:
        return err
    # /stop keeps agent refs during cooperative shutdown, so the status gate (not the
    # agent ref) is what rejects stop-then-steer.
    if status.get("status") != "running" or not hasattr(agent, "steer"):
        return _json_error(
            _openai_error, f"Run is not currently accepting steer input: {run_id}",
            code="run_not_accepting_steer", status=409)
    body, err = await self._read_json_body(request)
    if err:
        return err
    raw_text = body.get("input") or body.get("message") or body.get("text") or ""
    steer_text = _api_server._normalize_chat_content(raw_text).strip()
    if not steer_text:
        return _json_error(
            _openai_error, "Missing non-empty steer text; expected 'input', 'message', or 'text'.",
            code="invalid_steer_input", status=400)
    try:
        accepted = bool(agent.steer(steer_text))
    except Exception as exc:
        logger.exception("[api_server] steer failed for run %s", run_id)
        return _json_error(_openai_error, _api_server._redact_api_error_text(exc), code="steer_failed", status=500)
    if not accepted:
        return _json_error(
            _openai_error, f"Run did not accept steer text: {run_id}", code="steer_not_accepted", status=409)
    _mark_run_event(self, run_id, "run.steered", accepted=True)
    return web.json_response({"object": "hermes.run.steer", "run_id": run_id, "accepted": True})


async def _handle_stop_run(self, request: "web.Request", *, _api_server) -> "web.Response":
    """POST /v1/runs/{run_id}/stop — interrupt a running agent."""
    _openai_error = _api_server._openai_error
    run_id, status, agent, task, err = await _load_owned_run_async(
        self, request, _api_server=_api_server, permission="stop", active_fallback=True)
    if err is not None:
        return err
    if status.get("status") in TERMINAL_STATUSES:
        if run_id in self._protected_run_ids:
            try:
                await _await_protected_status(self, run_id)
            except Exception:
                return _json_error(_openai_error, "Protected stop status unavailable",
                                   code="recovery_status_unavailable", status=503)
        return web.json_response(status)
    if agent is None and task is None:
        return _json_error(
            _openai_error, f"Run is not active in this gateway process: {run_id}",
            code="run_not_active", status=409)
    self._set_run_status(run_id, "stopping", last_event="run.stopping")
    self._stopping_run_ids.add(run_id)
    if agent is not None:
        with suppress(Exception):
            _api_server.request_hard_interrupt(agent, "Stop requested via API")
        # Reap only this run's background processes (epoch-gated inside, so a concurrent
        # run on the same session_id keeps its own); no-op if the run already finished.
        _api_server._reap_disconnected_agent_processes(agent, source="api_server_run_stop")
    if run_id in self._protected_run_ids:
        try:
            await _await_protected_status(self, run_id)
        except Exception:
            return _json_error(_openai_error, "Protected stop status unavailable",
                               code="recovery_status_unavailable", status=503)
    return web.json_response({"run_id": run_id, "status": "stopping"})


async def _sweep_orphaned_runs(self) -> None:
    """Periodically expire transport buffers and terminal status records."""
    while True:
        await asyncio.sleep(60)
        self._sweep_orphaned_runs_once(time.time())


def _sweep_orphaned_runs_once(self, now: Optional[float] = None) -> None:
    """Expire old SSE buffers without treating transport age as run age."""
    if now is None:
        now = time.time()
    _tool_diag.sweep(self, now)
    for run_id, created_at in list(self._run_streams_created.items()):
        if now - created_at <= self._RUN_STREAM_TTL or run_id in self._run_stream_subscribers:
            continue
        logger.debug("[api_server] sweeping expired run transport %s", run_id)
        task = self._active_run_tasks.get(run_id)
        # Transport TTL bounds buffering; live control state survives until the task returns.
        _drop_run_transport(self, run_id)
        if task is None or task.done():
            _unregister_approval_notify(self._run_approval_sessions.get(run_id))
            _retire_live_run(self, run_id)
    for run_id, status in list(self._run_statuses.items()):
        if (status.get("status") in {"completed", "failed", "cancelled"}
                and now - float(status.get("updated_at", 0) or 0) > self._RUN_STATUS_TTL):
            _forget_run(self, run_id, self._run_statuses, self._run_idempotency_ids)
