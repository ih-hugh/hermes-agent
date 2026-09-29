"""Owner-only, bounded HTTP reader and finalizer for protected recovery sessions."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import hmac
import re
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from contextvars import copy_context
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterator, TypeVar, cast

try:
    from aiohttp import web
except ImportError:  # API server itself is optional.
    web = None  # type: ignore[assignment]

from gateway.platforms.api_server_recovery_artifacts import (
    MAX_RESPONSE_BYTES,
    MAX_ROUTE_PAGES,
    bounded_response_bytes,
    strict_json_loads,
)
from gateway.platforms.api_server_recovery_contract import (
    RecoveryCapabilities,
    RecoveryLimits,
    RecoveryReason,
    SealRequest,
    SealResult,
)
from hermes_state_recovery import RecoveryRefused, RecoveryScope, RecoveryStore
from hermes_state_recovery_deadline import (
    RecoveryDeadlineExceeded,
    acquire_recovery_lock,
    recovery_deadline,
    require_time,
)

if TYPE_CHECKING:
    from gateway.platforms.api_server import APIServerAdapter

_REQUEST_BYTES = 16_384
_WORKER_SECONDS = 5.0
_MAX_WORKERS = 2
_ReadResult = TypeVar("_ReadResult")


class RecoveryHttpRefused(ValueError):
    """Safe HTTP refusal; never carries request bodies or credentials."""

    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveryOwnerContext:
    profile: str
    home: Path
    scope_digest: str


@dataclass(frozen=True, slots=True)
class RecoveryWork:
    future: concurrent.futures.Future[bytes]
    deadline: float


def _authorization_values(request: web.Request) -> tuple[str, ...]:
    getall = getattr(request.headers, "getall", None)
    if callable(getall):
        return tuple(getall("Authorization", []))
    value = request.headers.get("Authorization")
    return (value,) if value is not None else ()


def capture_owner_context(
    adapter: APIServerAdapter,
    request: web.Request,
    *,
    selected_profile: str | None,
) -> RecoveryOwnerContext:
    """Capture physical profile/home and existing opaque owner scope on the loop thread."""
    from hermes_cli.auth import has_usable_secret
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home

    values = _authorization_values(request)
    if adapter._room_grant_token(request):
        raise RecoveryHttpRefused(401, "recovery_owner_auth_required")
    # Duplicate Authorization headers cannot add a room grant beside a bearer.
    if len(values) != 1 or not values[0].startswith("Bearer "):
        raise RecoveryHttpRefused(401, "recovery_owner_auth_required")
    token = values[0][7:].strip()
    key = adapter._expected_api_key()
    if not has_usable_secret(key, min_length=16) or not hmac.compare_digest(
        token.encode(), key.encode()
    ):
        raise RecoveryHttpRefused(401, "recovery_owner_auth_required")
    profile = selected_profile or get_active_profile_name()
    if not profile:
        raise RecoveryHttpRefused(503, "recovery_profile_unavailable")
    home = get_hermes_home()
    if not isinstance(home, Path) or not home.is_absolute():
        raise RecoveryHttpRefused(503, "recovery_profile_unavailable")
    # Preserve the pre-existing owner namespace. The physical profile above is
    # intentionally distinct for an unprefixed named-base listener.
    digest = hashlib.sha256(
        f"{selected_profile or 'default'}\0{key}".encode("utf-8")
    ).hexdigest()
    return RecoveryOwnerContext(profile, home, digest)


def recovery_enabled() -> bool:
    """Require the selected profile's explicit recovery.enabled: true YAML value."""
    from hermes_cli.config import (
        get_active_config_parse_failure,
        read_raw_config_readonly,
    )

    try:
        config = read_raw_config_readonly()
        if get_active_config_parse_failure() is not None:
            return False
        platforms = config.get("platforms") if isinstance(config, dict) else None
        api = platforms.get("api_server") if isinstance(platforms, dict) else None
        recovery = api.get("recovery") if isinstance(api, dict) else None
        return isinstance(recovery, dict) and recovery.get("enabled") is True
    except Exception:
        return False


class RecoveryWorkerPool:
    """Two actual workers, no waiting queue and no early release on lost awaiters."""

    def __init__(self) -> None:
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=_MAX_WORKERS, thread_name_prefix="hermes-recovery"
        )
        self._permits = threading.BoundedSemaphore(_MAX_WORKERS)
        self._lock = threading.Lock()
        self._futures: set[concurrent.futures.Future[bytes]] = set()
        self._accepting = True

    def submit(self, fn: Callable[[float], bytes]) -> RecoveryWork:
        # The loop calls this before any store acquisition or provider work.
        with self._lock:
            if not self._accepting:
                raise RecoveryHttpRefused(503, "recovery_shutting_down")
            if not self._permits.acquire(blocking=False):
                raise RecoveryHttpRefused(429, "recovery_workers_busy")
            deadline = time.monotonic() + _WORKER_SECONDS
            context = copy_context()
            try:
                future = cast(
                    concurrent.futures.Future[bytes],
                    self._executor.submit(context.run, self._run, fn, deadline),
                )
            except BaseException:
                self._permits.release()
                raise
            self._futures.add(future)
        future.add_done_callback(self._settled)
        return RecoveryWork(future, deadline)

    @staticmethod
    def _run(fn: Callable[[float], bytes], deadline: float) -> bytes:
        with recovery_deadline(deadline):
            result = fn(deadline)
            require_time()
            return result

    def _settled(self, future: concurrent.futures.Future[bytes]) -> None:
        try:
            future.exception()  # collect even when its HTTP awaiter disappeared
        except concurrent.futures.CancelledError:
            pass
        finally:
            with self._lock:
                self._futures.discard(future)
                self._permits.release()

    async def join(self) -> bool:
        """Stop admission and join real threads; return whether await was cancelled."""
        with self._lock:
            self._accepting = False
        join_task = asyncio.create_task(
            asyncio.to_thread(self._executor.shutdown, wait=True, cancel_futures=False)
        )
        cancelled = False
        while not join_task.done():
            try:
                await asyncio.shield(join_task)
            except asyncio.CancelledError:
                cancelled = True
        await join_task
        return cancelled


class _ReadOnlyDB:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def _read_retrying_ioerr(
        self, fn: Callable[[sqlite3.Connection], _ReadResult]
    ) -> _ReadResult:
        require_time()
        result = fn(self._conn)
        require_time()
        return result


class _ReadOnlyRecoveryView:
    """Only the immutable sealer read interface; no ledger write authority."""

    def __init__(self, conn: sqlite3.Connection, scope: RecoveryScope):
        self.db = _ReadOnlyDB(conn)
        self.store_id = scope.store_id
        self._scope = scope

    def _check_scope(self, scope: RecoveryScope) -> None:
        if scope != self._scope:
            raise RecoveryRefused("scope_mismatch")


@contextmanager
def _read_scope_for_root(
    owner: RecoveryOwnerContext, root_id: str
) -> Iterator[tuple[_ReadOnlyRecoveryView, RecoveryScope, tuple[int, int]]]:
    """Prove an existing protected root without a writable SessionDB open."""
    from hermes_state_dbfile import _connect_tracked_db
    from hermes_state_recovery_exclusions import _catalog, _protected_exists

    if not root_id or len(root_id) > 255:
        raise RecoveryHttpRefused(404, "recovery_not_found")
    path = owner.home / "state.db"
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise RecoveryHttpRefused(404, "recovery_not_found") from exc
    if not stat.S_ISREG(before.st_mode) or not before.st_dev or not before.st_ino:
        raise RecoveryHttpRefused(503, "recovery_store_unavailable")
    identity = before.st_dev, before.st_ino
    require_time()
    try:
        conn = _connect_tracked_db(
            path.absolute().as_uri() + "?mode=ro",
            tracking_path=path,
            uri=True,
            check_same_thread=False,
            isolation_level=None,
            timeout=0,
        )
    except sqlite3.OperationalError:
        require_time()
        raise
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=0")

        def _progress() -> int:
            try:
                require_time()
            except RecoveryDeadlineExceeded:
                return 1
            return 0

        conn.set_progress_handler(_progress, 1000)
        try:
            conn.execute("BEGIN")
            require_time()
            catalog = _catalog(conn)
            if catalog != "full" or not _protected_exists(conn, catalog):
                raise RecoveryHttpRefused(404, "recovery_not_found")
            store_meta = conn.execute(
                "SELECT typeof(store_id),length(substr(CAST(store_id AS BLOB),1,129)) "
                "FROM recovery_store WHERE singleton=1"
            ).fetchone()
            if (
                store_meta is None
                or store_meta[0] != "text"
                or type(store_meta[1]) is not int
                or not 0 < store_meta[1] <= 128
            ):
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
            store_id = conn.execute(
                "SELECT store_id FROM recovery_store WHERE singleton=1"
            ).fetchone()[0]
            metadata = conn.execute(
                "SELECT typeof(s.session_id),"
                "length(substr(CAST(s.session_id AS BLOB),1,256)) "
                "FROM recovery_sessions s JOIN recovery_members m "
                "ON m.run_id=s.root_run_id AND m.session_id=s.session_id "
                "WHERE s.root_run_id=? AND s.profile=? AND s.scope_digest=? "
                "AND m.generation=0 AND m.profile=? AND m.scope_digest=? LIMIT 2",
                (
                    root_id,
                    owner.profile,
                    owner.scope_digest,
                    owner.profile,
                    owner.scope_digest,
                ),
            ).fetchall()
            require_time()
            if (
                len(metadata) != 1
                or metadata[0][0] != "text"
                or type(metadata[0][1]) is not int
                or not 0 < metadata[0][1] <= 255
            ):
                raise RecoveryHttpRefused(404, "recovery_not_found")
            row = conn.execute(
                "SELECT s.session_id FROM recovery_sessions s "
                "WHERE s.root_run_id=? AND s.profile=? AND s.scope_digest=? LIMIT 2",
                (root_id, owner.profile, owner.scope_digest),
            ).fetchall()
            require_time()
            if (
                len(row) != 1
                or type(row[0][0]) is not str
                or len(row[0][0].encode()) != metadata[0][1]
            ):
                raise RecoveryHttpRefused(404, "recovery_not_found")
            scope = RecoveryScope(
                store_id, owner.profile, owner.scope_digest, row[0][0]
            )
            conn.execute("COMMIT")
        except sqlite3.OperationalError as exc:
            conn.set_progress_handler(None, 0)
            conn.rollback()
            try:
                require_time()
            except RecoveryDeadlineExceeded as deadline_exc:
                raise deadline_exc from exc
            raise
        except BaseException:
            conn.set_progress_handler(None, 0)
            conn.rollback()
            raise
        finally:
            conn.set_progress_handler(None, 0)
        require_time()
        current = path.lstat()
        if (current.st_dev, current.st_ino) != identity:
            raise RecoveryHttpRefused(503, "recovery_store_unavailable")
        yield _ReadOnlyRecoveryView(conn, scope), scope, identity
        require_time()
        current = path.lstat()
        if (current.st_dev, current.st_ino) != identity:
            raise RecoveryHttpRefused(503, "recovery_store_unavailable")
    finally:
        conn.close()


def _cached_writer_for_scope(
    adapter: APIServerAdapter,
    owner: RecoveryOwnerContext,
    scope: RecoveryScope,
    identity: tuple[int, int],
) -> RecoveryStore:
    """Use only the writer already retained by this process's protected admission."""
    with acquire_recovery_lock(adapter._session_db_cache_lock):
        db = adapter._session_db or adapter._session_dbs.get(str(owner.home))
    if (
        db is None
        or db.read_only
        or Path(db.db_path).resolve() != (owner.home / "state.db").resolve()
        or db._db_file_identity != identity
    ):
        raise RecoveryHttpRefused(503, "recovery_store_unavailable")
    try:
        current = (owner.home / "state.db").lstat()
    except OSError as exc:
        raise RecoveryHttpRefused(503, "recovery_store_unavailable") from exc
    if (current.st_dev, current.st_ino) != identity:
        raise RecoveryHttpRefused(503, "recovery_store_unavailable")
    store = RecoveryStore(db)
    if store.store_id != scope.store_id:
        raise RecoveryHttpRefused(503, "recovery_store_unavailable")
    return store


def _body_request(raw: bytes, root_id: str) -> SealRequest:
    try:
        value = strict_json_loads(raw, max_bytes=_REQUEST_BYTES)
        request = SealRequest.model_validate(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryHttpRefused(400, "recovery_request_invalid") from exc
    if request.run_ids[0] != root_id:
        raise RecoveryHttpRefused(400, "recovery_root_mismatch")
    return request


async def _read_body(request: web.Request) -> bytes:
    if request.content_length is not None and request.content_length > _REQUEST_BYTES:
        raise RecoveryHttpRefused(413, "recovery_request_oversized")
    parts: list[bytes] = []
    size = 0
    while True:
        chunk = await request.content.read(_REQUEST_BYTES - size + 1)
        if not chunk:
            break
        size += len(chunk)
        if size > _REQUEST_BYTES:
            raise RecoveryHttpRefused(413, "recovery_request_oversized")
        parts.append(chunk)
    return b"".join(parts)


def _post_worker(
    adapter: APIServerAdapter,
    owner: RecoveryOwnerContext,
    root_id: str,
    request: SealRequest,
    deadline: float,
) -> bytes:
    from gateway.platforms import api_server_runs as runs
    from hermes_state_recovery_seal import (
        finalize,
        prepare_provider_evidence,
        read_committed_seal_bytes,
    )

    with _read_scope_for_root(owner, root_id) as (view, scope, identity):
        prior = read_committed_seal_bytes(
            view, scope, root_id, request, deadline=deadline
        )
    if prior is not None:
        runs._retire_selected_provider_identity(adapter, scope)
        return prior
    store = _cached_writer_for_scope(adapter, owner, scope, identity)
    view = store.begin_close(scope, request)
    if view.state == "unsupported":
        return bounded_response_bytes(
            SealResult(
                schema="hermes.recovery/v1",
                state="unsupported",
                request_id=request.request_id,
                reasons=cast(tuple[RecoveryReason, ...], view.reason_codes),
            )
        )
    if any(member.producer_state != "closed" for member in view.members):
        return bounded_response_bytes(
            SealResult(
                schema="hermes.recovery/v1",
                state="pending",
                request_id=request.request_id,
                reasons=("producer_open",),
            )
        )
    capture = runs._selected_provider_capture_for_scope(adapter, scope, store)
    evidence = prepare_provider_evidence(capture, deadline=deadline)
    result = finalize(store, scope, request, evidence, deadline=deadline)
    if result.state != "sealed":
        return bounded_response_bytes(result)
    # Finalize returning sealed is the confirmed commit boundary. A response
    # readback can still fail under the same deadline, but identity retirement
    # must not depend on the HTTP response making it to the client.
    runs._retire_selected_provider_identity(adapter, scope)
    saved = read_committed_seal_bytes(store, scope, root_id, request, deadline=deadline)
    if saved is None:
        raise RecoveryHttpRefused(503, "recovery_seal_indeterminate")
    return saved


def _get_worker(
    adapter: APIServerAdapter,
    owner: RecoveryOwnerContext,
    root_id: str,
    page: int | None,
    deadline: float,
) -> bytes:
    from hermes_state_recovery_seal import read_seal_bytes, read_sealed_page_bytes

    with _read_scope_for_root(owner, root_id) as (view, scope, _identity):
        require_time()
        if page is None:
            return read_seal_bytes(view, scope, root_id, deadline=deadline)
        return read_sealed_page_bytes(view, scope, root_id, page, deadline=deadline)


def _error(exc: BaseException) -> web.Response:
    if isinstance(exc, RecoveryHttpRefused):
        status, code = exc.status, exc.code
    elif isinstance(exc, RecoveryDeadlineExceeded):
        status, code = 504, "recovery_deadline_exceeded"
    elif isinstance(exc, RecoveryRefused):
        if exc.code == "seal_deadline_exceeded":
            status = 504
        elif exc.code == "protected_session_authority_unavailable":
            status = 503
        elif exc.code in {
            "not_found",
            "seal_not_found",
            "sealed_page_not_found",
            "scope_mismatch",
        }:
            status = 404
        elif exc.code in {"close_conflict", "sealed_request_mismatch"}:
            status = 409
        else:
            status = 409
        code = exc.code
    elif isinstance(exc, sqlite3.Error):
        status, code = 503, "recovery_store_busy"
    else:
        status, code = 503, "recovery_unavailable"
    return web.json_response({"error": {"code": code}}, status=status)


async def _run(adapter: APIServerAdapter, fn: Callable[[float], bytes]) -> web.Response:
    try:
        work = adapter._recovery_workers.submit(fn)
        wrapped = asyncio.wrap_future(work.future)
        # A timed-out or cancelled HTTP awaiter cannot abandon the wrapper's
        # later exception. The pool separately retains the real worker slot.
        wrapped.add_done_callback(_collect_async_result)
        raw = await asyncio.wait_for(
            asyncio.shield(wrapped),
            timeout=max(0.0, work.deadline - time.monotonic()),
        )
        if type(raw) is not bytes or len(raw) > MAX_RESPONSE_BYTES:
            raise RecoveryHttpRefused(503, "recovery_response_oversized")
        return web.Response(body=raw, content_type="application/json")
    except asyncio.TimeoutError:
        return _error(RecoveryDeadlineExceeded("recovery_deadline_exceeded"))
    except asyncio.CancelledError:
        raise  # underlying worker retains its slot and result collection
    except BaseException as exc:
        return _error(exc)


def _collect_async_result(future: asyncio.Future[bytes]) -> None:
    try:
        future.exception()
    except asyncio.CancelledError:
        pass


def _owner_or_error(
    adapter: APIServerAdapter, request: web.Request, *, _api_server
) -> RecoveryOwnerContext | web.Response:
    if not recovery_enabled():
        return _error(RecoveryHttpRefused(404, "recovery_disabled"))
    try:
        return capture_owner_context(
            adapter, request, selected_profile=_api_server._api_request_profile.get()
        )
    except RecoveryHttpRefused as exc:
        return _error(exc)


async def handle_capabilities(
    adapter: APIServerAdapter, request: web.Request, *, _api_server
) -> web.Response:
    owner = _owner_or_error(adapter, request, _api_server=_api_server)
    if isinstance(owner, web.Response):
        return owner
    if request.query_string:
        return _error(RecoveryHttpRefused(400, "recovery_query_invalid"))
    from gateway.platforms.api_server_recovery_artifacts import (
        MAX_ACCOUNTING_BYTES,
        MAX_DOCUMENT_BYTES,
        MAX_OTHER_PAGE_ROWS,
        MAX_SNAPSHOT_BYTES,
        MAX_TRANSCRIPT_PAGE_ROWS,
        MAX_TRANSCRIPT_ROWS,
    )

    limits = RecoveryLimits(
        max_request_bytes=_REQUEST_BYTES,
        max_response_bytes=MAX_RESPONSE_BYTES,
        max_route_pages=MAX_ROUTE_PAGES,
        max_snapshot_bytes=MAX_SNAPSHOT_BYTES,
        max_transcript_rows=MAX_TRANSCRIPT_ROWS,
        max_transcript_page_rows=MAX_TRANSCRIPT_PAGE_ROWS,
        max_other_page_rows=MAX_OTHER_PAGE_ROWS,
        max_receipt_bytes=MAX_DOCUMENT_BYTES,
        max_accounting_bytes=MAX_ACCOUNTING_BYTES,
        max_active_seal_seconds=5,
        max_workers=_MAX_WORKERS,
    )
    wire = RecoveryCapabilities.model_validate({
        "schema": "hermes.recovery-capabilities/v1",
        "enabled": True,
        "ready": False,
        "limits": limits.model_dump(),
    })
    return web.Response(
        body=wire.model_dump_json(by_alias=True).encode(),
        content_type="application/json",
    )


async def handle_post_seal(
    adapter: APIServerAdapter, request: web.Request, *, _api_server
) -> web.Response:
    owner = _owner_or_error(adapter, request, _api_server=_api_server)
    if isinstance(owner, web.Response):
        return owner
    if request.query_string:
        return _error(RecoveryHttpRefused(400, "recovery_query_invalid"))
    root_id = request.match_info.get("root_id", "")
    try:
        raw = await _read_body(request)
        seal_request = _body_request(raw, root_id)
    except RecoveryHttpRefused as exc:
        return _error(exc)
    return await _run(
        adapter,
        lambda deadline: _post_worker(adapter, owner, root_id, seal_request, deadline),
    )


async def handle_get_seal(
    adapter: APIServerAdapter, request: web.Request, *, _api_server
) -> web.Response:
    owner = _owner_or_error(adapter, request, _api_server=_api_server)
    if isinstance(owner, web.Response):
        return owner
    if request.query_string:
        return _error(RecoveryHttpRefused(400, "recovery_query_invalid"))
    root_id = request.match_info.get("root_id", "")
    return await _run(
        adapter, lambda deadline: _get_worker(adapter, owner, root_id, None, deadline)
    )


async def handle_get_page(
    adapter: APIServerAdapter, request: web.Request, *, _api_server
) -> web.Response:
    owner = _owner_or_error(adapter, request, _api_server=_api_server)
    if isinstance(owner, web.Response):
        return owner
    match = re.fullmatch(r"page=(0|[1-9][0-9]*)", request.query_string)
    if match is None:
        return _error(
            RecoveryHttpRefused(
                404 if not request.query_string else 400, "recovery_page_invalid"
            )
        )
    digits = match.group(1)
    if len(digits) > len(str(MAX_ROUTE_PAGES - 1)):
        return _error(RecoveryHttpRefused(404, "recovery_page_not_found"))
    page = int(digits)
    if page >= MAX_ROUTE_PAGES:
        return _error(RecoveryHttpRefused(404, "recovery_page_not_found"))
    root_id = request.match_info.get("root_id", "")
    return await _run(
        adapter, lambda deadline: _get_worker(adapter, owner, root_id, page, deadline)
    )


def http_routes(adapter: APIServerAdapter) -> list[tuple[str, str, Callable]]:
    return [
        ("GET", "/v1/recovery/capabilities", adapter._handle_recovery_capabilities),
        ("POST", "/v1/runs/{root_id}/seal", adapter._handle_recovery_post_seal),
        ("GET", "/v1/runs/{root_id}/seal", adapter._handle_recovery_get_seal),
        (
            "GET",
            "/v1/runs/{root_id}/sealed-transcript",
            adapter._handle_recovery_get_page,
        ),
    ]
