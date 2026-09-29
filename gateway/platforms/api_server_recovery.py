"""Owner-only, bounded HTTP reader and finalizer for protected recovery sessions."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import hmac
import math
import re
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from contextvars import copy_context
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Generic, Iterator, Literal, TypeVar, cast

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
    RecoveryAdmission,
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
_WorkResult = TypeVar("_WorkResult")


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
class RecoveryWork(Generic[_WorkResult]):
    future: concurrent.futures.Future[_WorkResult]
    deadline: float


@dataclass(frozen=True, slots=True)
class ProtectedKeyReplay:
    outcome: Literal["replayed", "conflict"]
    run_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ProtectedRunRead:
    store_id: str
    status: dict[str, object]


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
        self._futures: set[concurrent.futures.Future[object]] = set()
        self._accepting = True

    def submit(
        self,
        fn: Callable[[float], _WorkResult],
        *,
        deadline: float | None = None,
    ) -> RecoveryWork[_WorkResult]:
        # The loop calls this before any store acquisition or provider work.
        with self._lock:
            if not self._accepting:
                raise RecoveryHttpRefused(503, "recovery_shutting_down")
            if not self._permits.acquire(blocking=False):
                raise RecoveryHttpRefused(429, "recovery_workers_busy")
            now = time.monotonic()
            if deadline is not None and (
                type(deadline) is not float or not math.isfinite(deadline)
            ):
                self._permits.release()
                raise RecoveryDeadlineExceeded("recovery_deadline_invalid")
            deadline = (
                min(deadline, now + _WORKER_SECONDS)
                if deadline is not None
                else now + _WORKER_SECONDS
            )
            if deadline <= now:
                self._permits.release()
                raise RecoveryDeadlineExceeded("recovery_deadline_exceeded")
            context = copy_context()
            try:
                future = cast(
                    concurrent.futures.Future[_WorkResult],
                    self._executor.submit(context.run, self._run, fn, deadline),
                )
            except BaseException:
                self._permits.release()
                raise
            self._futures.add(cast(concurrent.futures.Future[object], future))
        future.add_done_callback(self._settled)
        return RecoveryWork(future, deadline)

    @staticmethod
    def _run(fn: Callable[[float], _WorkResult], deadline: float) -> _WorkResult:
        with recovery_deadline(deadline):
            return fn(deadline)

    def _settled(self, future: concurrent.futures.Future[_WorkResult]) -> None:
        try:
            future.exception()  # collect even when its HTTP awaiter disappeared
        except concurrent.futures.CancelledError:
            pass
        finally:
            with self._lock:
                self._futures.discard(cast(concurrent.futures.Future[object], future))
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
def _protected_read_snapshot(
    owner: RecoveryOwnerContext,
) -> Iterator[tuple[sqlite3.Connection, str, tuple[int, int]]]:
    """One tracked, protected, query-only snapshot on the selected physical home."""
    from hermes_state_dbfile import _connect_tracked_db
    from hermes_state_recovery_exclusions import _catalog, _protected_exists

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
            yield conn, store_id, identity
            if conn.in_transaction:
                conn.execute("COMMIT")
            require_time()
            current = path.lstat()
            if (current.st_dev, current.st_ino) != identity:
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
        except sqlite3.OperationalError as exc:
            conn.set_progress_handler(None, 0)
            if conn.in_transaction:
                conn.rollback()
            try:
                require_time()
            except RecoveryDeadlineExceeded as deadline_exc:
                raise deadline_exc from exc
            raise
        except BaseException:
            conn.set_progress_handler(None, 0)
            if conn.in_transaction:
                conn.rollback()
            raise
    finally:
        conn.set_progress_handler(None, 0)
        conn.close()


@contextmanager
def _read_scope_for_root(
    owner: RecoveryOwnerContext, root_id: str
) -> Iterator[tuple[_ReadOnlyRecoveryView, RecoveryScope, tuple[int, int]]]:
    """Prove an existing protected root without a writable SessionDB open."""
    if not root_id or len(root_id) > 255:
        raise RecoveryHttpRefused(404, "recovery_not_found")
    with _protected_read_snapshot(owner) as (conn, store_id, identity):
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
        scope = RecoveryScope(store_id, owner.profile, owner.scope_digest, row[0][0])
        conn.execute("COMMIT")
        conn.set_progress_handler(None, 0)
        yield _ReadOnlyRecoveryView(conn, scope), scope, identity


def read_protected_key(
    owner: RecoveryOwnerContext,
    session_id: str,
    key: str,
    fingerprint: str,
    admission: RecoveryAdmission,
) -> ProtectedKeyReplay | None:
    """Read one committed admission without creating a writer or granting work."""
    from gateway.platforms.api_server_recovery_artifacts import strict_json_loads

    try:
        with _protected_read_snapshot(owner) as (conn, _store_id, _identity):
            metadata = conn.execute(
                "SELECT typeof(run_id),length(substr(CAST(run_id AS BLOB),1,256)),"
                "typeof(session_id),length(substr(CAST(session_id AS BLOB),1,256)),"
                "typeof(parent_run_id),length(substr(CAST(parent_run_id AS BLOB),1,256)),"
                "typeof(request_sha256),length(substr(CAST(request_sha256 AS BLOB),1,65)),"
                "typeof(status_json),length(substr(CAST(status_json AS BLOB),1,131073)),"
                "typeof(generation),generation FROM recovery_members "
                "WHERE profile=? AND scope_digest=? AND idempotency_key=?",
                (owner.profile, owner.scope_digest, key),
            ).fetchone()
            require_time()
            if metadata is None:
                return None
            if (
                metadata[0] != "text"
                or type(metadata[1]) is not int
                or not 0 < metadata[1] <= 255
                or metadata[2] != "text"
                or type(metadata[3]) is not int
                or not 0 < metadata[3] <= 255
                or not (
                    (metadata[4] == "null" and metadata[5] is None)
                    or (
                        metadata[4] == "text"
                        and type(metadata[5]) is int
                        and 0 < metadata[5] <= 255
                    )
                )
                or metadata[6] != "text"
                or metadata[7] != 64
                or metadata[8] != "text"
                or type(metadata[9]) is not int
                or not 0 < metadata[9] <= MAX_RESPONSE_BYTES
                or metadata[10] != "integer"
                or metadata[11] not in (0, 1)
            ):
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
            row = conn.execute(
                "SELECT run_id,session_id,generation,parent_run_id,request_sha256,status_json "
                "FROM recovery_members WHERE profile=? AND scope_digest=? AND idempotency_key=?",
                (owner.profile, owner.scope_digest, key),
            ).fetchone()
            require_time()
            if row is None or any(
                type(row[index]) is not str for index in (0, 1, 4, 5)
            ):
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
            if (
                row[1] != session_id
                or row[2] != admission.generation
                or row[3] != admission.parent_run_id
                or not hmac.compare_digest(row[4], fingerprint)
            ):
                return ProtectedKeyReplay("conflict", row[0], "queued")
            try:
                status = strict_json_loads(
                    row[5].encode("utf-8"), max_bytes=MAX_RESPONSE_BYTES
                )
                state = (
                    cast(dict[str, object], status).get("status")
                    if type(status) is dict
                    else None
                )
                if type(state) is not str or not state or len(state) > 64:
                    raise ValueError("invalid protected status")
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise RecoveryHttpRefused(503, "recovery_store_unavailable") from exc
            return ProtectedKeyReplay("replayed", row[0], state)
    except RecoveryHttpRefused as exc:
        if exc.status == 404:
            return None
        raise


def read_protected_run_status(
    owner: RecoveryOwnerContext, run_id: str
) -> ProtectedRunRead | None:
    """Read one owned protected status from its physical home, without a writer."""
    if type(run_id) is not str or not 0 < len(run_id) <= 255:
        return None
    try:
        with _protected_read_snapshot(owner) as (conn, store_id, _identity):
            metadata = conn.execute(
                "SELECT typeof(status_json),"
                "length(substr(CAST(status_json AS BLOB),1,131073)) "
                "FROM recovery_members WHERE run_id=? AND profile=? AND scope_digest=?",
                (run_id, owner.profile, owner.scope_digest),
            ).fetchone()
            require_time()
            if metadata is None:
                return None
            if (
                metadata[0] != "text"
                or type(metadata[1]) is not int
                or not 0 < metadata[1] <= MAX_RESPONSE_BYTES
            ):
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
            row = conn.execute(
                "SELECT status_json FROM recovery_members "
                "WHERE run_id=? AND profile=? AND scope_digest=?",
                (run_id, owner.profile, owner.scope_digest),
            ).fetchone()
            require_time()
            if (
                row is None
                or type(row[0]) is not str
                or len(row[0].encode()) != metadata[1]
            ):
                raise RecoveryHttpRefused(503, "recovery_store_unavailable")
            try:
                value = strict_json_loads(row[0].encode(), max_bytes=MAX_RESPONSE_BYTES)
                if type(value) is not dict:
                    raise ValueError("invalid status")
                status = cast(dict[str, object], value).get("status")
                if type(status) is not str or not status or len(status) > 64:
                    raise ValueError("invalid status")
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise RecoveryHttpRefused(503, "recovery_store_unavailable") from exc
            return ProtectedRunRead(store_id, cast(dict[str, object], value))
    except RecoveryHttpRefused as exc:
        if exc.status == 404:
            return None
        raise


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

    def _capabilities_worker(deadline: float) -> bytes:
        from gateway.platforms.api_server_recovery_runtime import static_runtime_ready

        wire = RecoveryCapabilities.model_validate({
            "schema": "hermes.recovery-capabilities/v1",
            "enabled": True,
            "ready": static_runtime_ready(owner, deadline=deadline),
            "limits": limits.model_dump(),
        })
        return wire.model_dump_json(by_alias=True).encode()

    return await _run(adapter, _capabilities_worker)


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
