"""Connection-local write authority for explicitly protected recovery sessions.

SQLite executes these functions from row triggers in the writer's transaction. A
second connection without the functions cannot write through the triggers.
"""

from __future__ import annotations

import sqlite3
import weakref
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable, Iterator, TypeVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hermes_state import SessionDB


_ROWS = {
    "sessions": "id",
    "messages": "session_id",
    "session_model_usage": "session_id",
}
_MUTATION = {
    "sessions": "session",
    "messages": "message",
    "session_model_usage": "usage",
}
_LEDGER = (
    "recovery_store",
    "recovery_sessions",
    "recovery_members",
    "recovery_producers",
    "recovery_root_done",
    "recovery_sends",
    "recovery_usage_slots",
    "recovery_write_acks",
    "recovery_provider_admissions",
    "recovery_provider_invocations",
    "recovery_seal_documents",
    "recovery_sealed_pages",
    "recovery_exclusions",
)
_INITIAL_METADATA_COLUMNS = (
    "user_id", "session_key", "chat_id", "chat_type", "thread_id",
    "display_name", "origin_json", "model", "model_config",
    "system_prompt_hash", "parent_session_id", "cwd",
)
_INITIAL_METADATA_MARKERS = _INITIAL_METADATA_COLUMNS
_INITIAL_METADATA_RESTRICTED = tuple(
    column for column in _INITIAL_METADATA_COLUMNS
    if column not in {"model", "model_config", "display_name"}
)
_IMMUTABLE_SOURCE_COLUMNS = ("source", "profile_name", "started_at", "system_prompt")
_MAX_GUARD_NAME_BYTES = 128
_MAX_GUARD_SQL_BYTES = 16 * 1024
_MAX_SESSION_GUARD_COLUMNS = 128
_INITIAL_METADATA: ContextVar[tuple[int, int, int, str, str, int, int] | None] = ContextVar(
    "recovery_initial_session_metadata", default=None,
)
T = TypeVar("T")


@contextmanager
def initial_session_metadata_write(
    db: SessionDB, conn: sqlite3.Connection, permit: object, session_id: str,
    run_id: str, generation: int,
) -> Iterator[None]:
    """Authorize one exact source-row NULL fill inside a guarded write callback."""
    from agent.recovery_producers import current_lease
    from hermes_state_recovery import RecoveryRefused

    lease = current_lease()
    if (
        lease is None or lease.kind != "executor"
        or lease.registry.store.db is not db
        or lease.registry.scope.session_id != session_id
        or lease.registry.run_id != run_id
        or lease.registry.generation != generation
    ):
        raise RecoveryRefused("session_init_executor_required")
    token = _INITIAL_METADATA.set(
        (id(db), id(conn), id(permit), session_id, run_id, generation, id(lease))
    )
    try:
        yield
    finally:
        _INITIAL_METADATA.reset(token)


@dataclass(frozen=True, slots=True)
class WriteAck:
    write_id: str
    payload_sha256: str
    revision: int
    result: object


def guarded_write(
    db: SessionDB,
    permit: object,
    mutation: str,
    write_id: str,
    payload_sha256: str,
    fn: Callable[[sqlite3.Connection], T],
) -> WriteAck:
    """Commit one protected mutation and its stable acknowledgement atomically."""
    from agent.recovery_context import (
        _generic_write,
        authorize_recovery_row,
        write_binding,
    )
    from hermes_state_recovery import RecoveryRefused, RecoveryStore

    store = RecoveryStore(db)
    binding = write_binding(permit, store)
    if (
        binding is None
        or mutation not in {"session", "message", "completion"}
        or not write_id
        or len(payload_sha256) != 64
    ):
        raise RecoveryRefused("invalid_write_permit")
    scope, run_id, generation = binding

    identity = (scope.session_id, run_id, generation, mutation, payload_sha256)

    def _committed_result(raw: str) -> object:
        if mutation == "message":
            from hermes_state_recovery_message_result import read_message_result

            return read_message_result(raw).to_ack_value()
        return json.loads(raw)

    def _existing(conn):
        row = conn.execute(
            "SELECT session_id,run_id,generation,mutation,payload_sha256,state,"
            "ack_revision,result_json FROM recovery_write_acks WHERE write_id=?",
            (write_id,),
        ).fetchone()
        if row is not None and tuple(row[:5]) != identity:
            raise RecoveryRefused("write_payload_conflict")
        return row

    def _reserve(conn):
        existing = _existing(conn)
        if existing is not None:
            if existing[5] == "committed":
                return WriteAck(
                    write_id, payload_sha256, existing[6], _committed_result(existing[7])
                )
            if existing[5] == "failed":
                raise RecoveryRefused("write_failed")
            return None
        with _generic_write(db, conn, permit):
            if not authorize_recovery_row(db, conn, scope.session_id, mutation):
                raise RecoveryRefused("invalid_write_permit")
        conn.execute(
            "INSERT INTO recovery_write_acks"
            "(write_id,session_id,run_id,generation,mutation,payload_sha256,state) "
            "VALUES(?,?,?,?,?,?,'pending')",
            (write_id, *identity),
        )
        return None

    committed = store._write(_reserve, patience_s=db._TRANSCRIPT_WRITE_PATIENCE_S)
    if committed is not None:
        return committed

    def _apply(conn):
        existing = _existing(conn)
        if existing is None or existing[5] != "pending":
            if existing is not None and existing[5] == "committed":
                return WriteAck(
                    write_id, payload_sha256, existing[6], _committed_result(existing[7])
                )
            raise RecoveryRefused("write_failed")
        with _generic_write(db, conn, permit):
            if not authorize_recovery_row(db, conn, scope.session_id, mutation):
                raise RecoveryRefused("invalid_write_permit")
            result = fn(conn)
        if mutation == "message":
            from hermes_state_recovery_message_result import read_message_result

            result = read_message_result(result).to_ack_value()
        conn.execute(
            "UPDATE recovery_sessions SET revision=revision+1 WHERE session_id=?",
            (scope.session_id,),
        )
        revision = conn.execute(
            "SELECT revision FROM recovery_sessions WHERE session_id=?",
            (scope.session_id,),
        ).fetchone()[0]
        conn.execute(
            "UPDATE recovery_write_acks SET state='committed',ack_revision=?,result_json=? "
            "WHERE write_id=? AND state='pending'",
            (revision, json.dumps(result, sort_keys=True), write_id),
        )
        return WriteAck(write_id, payload_sha256, revision, result)

    try:
        return store._write(_apply, patience_s=db._TRANSCRIPT_WRITE_PATIENCE_S)
    except BaseException:

        def _fail(conn):
            existing = _existing(conn)
            if existing is not None and existing[5] == "pending":
                conn.execute(
                    "UPDATE recovery_write_acks SET state='failed' "
                    "WHERE write_id=? AND state='pending'",
                    (write_id,),
                )
                store._add_reason(conn, scope, "untracked_write")
                store._settle_member(conn, scope, run_id)

        try:
            store._write(_fail, patience_s=db._TRANSCRIPT_WRITE_PATIENCE_S)
        except Exception:
            # An unavailable DB retains the pending row and member capacity.
            pass
        raise


_USAGE_SESSION_COLUMNS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "estimated_cost_usd",
    "actual_cost_usd",
    "cost_status",
    "cost_source",
    "pricing_version",
    "billing_provider",
    "billing_base_url",
    "billing_mode",
    "model",
    "api_call_count",
)
_USAGE_INSERT_COLUMNS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "estimated_cost_usd",
    "actual_cost_usd",
    "api_call_count",
)
_UNSUPPORTED_SESSION_COLUMNS = ("title", "title_source", "display_name", "model_config")


def register_connection_guard(conn: sqlite3.Connection, db: SessionDB) -> None:
    """Install only process-owned functions, never a SQL-settable bypass value."""
    from agent.recovery_context import authorize_recovery_row, authorize_recovery_store

    db_ref = weakref.ref(db)
    conn_ref = weakref.ref(conn)

    def _row_guard(session_id, mutation):
        live_db, live_conn = db_ref(), conn_ref()
        if mutation == "session_init" and live_db is not None and live_conn is not None:
            from agent.recovery_context import current_write_permit
            from agent.recovery_producers import current_lease
            from agent.recovery_context import current_incarnation

            permit = current_write_permit()
            lease = current_lease()
            record = _INITIAL_METADATA.get()
            if (
                record is not None and lease is not None and permit is not None
                and record == (id(live_db), id(live_conn), id(permit), session_id,
                               lease.registry.run_id, lease.registry.generation, id(lease))
                and lease.kind == "executor"
                and lease.registry.store.db is live_db
                and authorize_recovery_row(live_db, live_conn, session_id, "session")
            ):
                producer = live_conn.execute(
                    "SELECT state,owner_incarnation FROM recovery_producers "
                    "WHERE producer_id=? AND run_id=? AND kind='executor'",
                    (lease.producer_id, lease.registry.run_id),
                ).fetchone()
                return int(producer is not None and tuple(producer) == ("running", current_incarnation()))
            return 0
        return int(
            live_db is not None
            and live_conn is not None
            and authorize_recovery_row(live_db, live_conn, session_id, mutation)
        )

    def _store_guard():
        live_db, live_conn = db_ref(), conn_ref()
        return int(
            live_db is not None
            and live_conn is not None
            and authorize_recovery_store(live_db, live_conn)
        )

    conn.create_function(
        "recovery_row_guard",
        2,
        _row_guard,
    )
    conn.create_function(
        "recovery_store_guard",
        0,
        _store_guard,
    )


def _guard_statements(conn: sqlite3.Connection) -> Iterator[tuple[str, str]]:
    """One canonical source for guard installation and installed-body validation."""
    from hermes_state_recovery import RecoveryRefused

    columns_rows = conn.execute(
        "SELECT substr(name,1,129),length(CAST(name AS BLOB)) "
        "FROM pragma_table_info('sessions') LIMIT ?",
        (_MAX_SESSION_GUARD_COLUMNS + 1,),
    ).fetchall()
    if (not columns_rows or len(columns_rows) > _MAX_SESSION_GUARD_COLUMNS
            or any(type(name) is not str or type(size) is not int
                   or size > _MAX_GUARD_NAME_BYTES
                   or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
                   for name, size in columns_rows)):
        raise RecoveryRefused("protected_session_authority_unavailable")
    columns = [name for name, _size in columns_rows]
    for table, id_col in _ROWS.items():
        mutation = _MUTATION[table]
        for operation, identities in (
            ("INSERT", (f"NEW.{id_col}",)),
            ("UPDATE", (f"OLD.{id_col}", f"NEW.{id_col}")),
            ("DELETE", (f"OLD.{id_col}",)),
        ):
            name = f"recovery_guard_{table}_{operation.lower()}"
            checked_mutation = f"'{mutation}'"
            if operation == "DELETE":
                checked_mutation = "'delete'"
            if table == "sessions" and operation == "INSERT":
                nonzero = " OR ".join(
                    f"COALESCE(NEW.{column}, 0) != 0"
                    for column in _USAGE_INSERT_COLUMNS
                )
                checked_mutation = (
                    f"CASE WHEN {nonzero} THEN 'usage' ELSE 'session' END"
                )
            if table == "sessions" and operation == "UPDATE":
                allowed = set(_INITIAL_METADATA_COLUMNS)
                initial_only = " AND ".join(
                    f"OLD.{column} IS NEW.{column}" for column in columns if column not in allowed
                )
                null_fills = " AND ".join(
                    f"(OLD.{column} IS NULL OR OLD.{column} IS NEW.{column})"
                    for column in _INITIAL_METADATA_COLUMNS
                )
                initial_change = " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}"
                    for column in _INITIAL_METADATA_MARKERS
                )
                restricted_change = " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}"
                    for column in _INITIAL_METADATA_RESTRICTED
                )
                immutable_change = " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}"
                    for column in _IMMUTABLE_SOURCE_COLUMNS
                )
                changed = " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}"
                    for column in _USAGE_SESSION_COLUMNS
                )
                unsupported = " OR ".join(
                    f"OLD.{column} IS NOT NEW.{column}"
                    for column in _UNSUPPORTED_SESSION_COLUMNS
                )
                checked_mutation = (
                    f"CASE WHEN OLD.id IS NOT NEW.id THEN 'move' "
                    f"WHEN {immutable_change} THEN 'unsupported' "
                    f"WHEN ({initial_change}) AND ({initial_only}) AND ({null_fills}) "
                    "THEN 'session_init' "
                    f"WHEN {restricted_change} THEN 'unsupported' "
                    f"WHEN {unsupported} THEN 'unsupported' "
                    f"WHEN {changed} THEN 'usage' ELSE 'session' END"
                )
            elif operation == "UPDATE":
                checked_mutation = (
                    f"CASE WHEN OLD.{id_col} IS NOT NEW.{id_col} THEN 'move' "
                    f"ELSE '{mutation}' END"
                )
            checks = " AND ".join(
                f"recovery_row_guard({identity}, {checked_mutation}) = 1"
                for identity in identities
            )
            yield name, (
                f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE {operation} ON {table} "
                f"BEGIN SELECT CASE WHEN NOT ({checks}) THEN RAISE(ABORT, 'recovery_write_refused') END; END"
            )
    for table in _LEDGER:
        if table == "recovery_exclusions":
            # Its canonical bootstrap triggers accept only one exact raw-claim
            # operation; a general store guard would grant broader authority.
            continue
        for operation in ("INSERT", "UPDATE", "DELETE"):
            if table in {"recovery_seal_documents", "recovery_sealed_pages"}:
                name = f"recovery_guard_{table}_{operation.lower()}"
                if operation == "INSERT":
                    # BEFORE INSERT also runs for INSERT OR REPLACE, whose implicit
                    # DELETE does not run DELETE triggers by default in SQLite.
                    key = " AND route_page=NEW.route_page" if table == "recovery_sealed_pages" else ""
                    missing_document = (
                        "OR NOT EXISTS(SELECT 1 FROM recovery_seal_documents "
                        "WHERE session_id=NEW.session_id) "
                        if table == "recovery_sealed_pages" else ""
                    )
                    yield name, (
                        f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE INSERT ON {table} "
                        "BEGIN SELECT CASE WHEN recovery_store_guard() != 1 "
                        "OR NOT EXISTS(SELECT 1 FROM recovery_sessions "
                        "WHERE session_id=NEW.session_id AND phase='closing') "
                        f"OR EXISTS(SELECT 1 FROM {table} WHERE session_id=NEW.session_id{key}) "
                        f"{missing_document}"
                        "THEN RAISE(ABORT, 'recovery_immutable_seal') END; END"
                    )
                else:
                    # No holder, including the private writer, may mutate a seal.
                    yield name, (
                        f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE {operation} ON {table} "
                        "BEGIN SELECT RAISE(ABORT, 'recovery_immutable_seal'); END"
                    )
                continue
            name = f"recovery_guard_{table}_{operation.lower()}"
            yield name, (
                f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE {operation} ON {table} "
                "BEGIN SELECT CASE WHEN recovery_store_guard() != 1 "
                "THEN RAISE(ABORT, 'recovery_store_refused') END; END"
            )


def install_recovery_guards(conn: sqlite3.Connection) -> None:
    """Create opted-in triggers inside the admission transaction."""
    for _name, statement in _guard_statements(conn):
        conn.execute(statement)


def require_current_recovery_guards(conn: sqlite3.Connection) -> None:
    """Refuse stale, partial, or unrecognized installed recovery authority."""
    from hermes_state_recovery import RecoveryRefused
    from hermes_state_recovery_exclusions import EXCLUSION_NAMES, EXCLUSION_SQL

    exclusion_guards = EXCLUSION_NAMES - {"recovery_exclusions"}
    expected_count = 3 * (len(_ROWS) + len(_LEDGER) - 1) + len(exclusion_guards)
    try:
        # SQLite computes lengths without transferring an arbitrary trigger body
        # into Python. The +1 row detects any extra catalog entry.
        metadata = conn.execute(
            "SELECT length(CAST(type AS BLOB)),length(CAST(name AS BLOB)),"
            "length(CAST(sql AS BLOB)) FROM sqlite_master "
            "WHERE name GLOB 'recovery_guard_*' LIMIT ?",
            (expected_count + 1,),
        ).fetchall()
        if (len(metadata) > expected_count or any(
            type(type_size) is not int or not 0 < type_size <= 8
            or type(name_size) is not int or not 0 < name_size <= _MAX_GUARD_NAME_BYTES
            or type(sql_size) is not int or not 0 < sql_size <= _MAX_GUARD_SQL_BYTES
            for type_size, name_size, sql_size in metadata
        )):
            raise RecoveryRefused("protected_session_authority_unavailable")
        # Both fields are truncated at a fixed byte bound even if another
        # connection changes schema between the metadata and body queries.
        rows = conn.execute(
            "SELECT type,substr(CAST(name AS BLOB),1,?),"
            "substr(CAST(sql AS BLOB),1,?) FROM sqlite_master "
            "WHERE name GLOB 'recovery_guard_*' LIMIT ?",
            (_MAX_GUARD_NAME_BYTES + 1, _MAX_GUARD_SQL_BYTES + 1, expected_count + 1),
        ).fetchall()
        if len(rows) != len(metadata):
            raise RecoveryRefused("protected_session_authority_unavailable")
        actual: dict[str, bytes] = {}
        for kind, raw_name, raw_sql in rows:
            if (kind != "trigger" or type(raw_name) is not bytes
                    or type(raw_sql) is not bytes
                    or len(raw_name) > _MAX_GUARD_NAME_BYTES
                    or len(raw_sql) > _MAX_GUARD_SQL_BYTES):
                raise RecoveryRefused("protected_session_authority_unavailable")
            try:
                name = raw_name.decode("utf-8")
            except UnicodeError as exc:
                raise RecoveryRefused("protected_session_authority_unavailable") from exc
            if name in actual:
                raise RecoveryRefused("protected_session_authority_unavailable")
            actual[name] = raw_sql

        expected_exclusions = {
            statement.split(" ", 6)[5]: statement.replace(" IF NOT EXISTS", "", 1).encode("utf-8")
            for statement in EXCLUSION_SQL[1:]
        }
        if set(expected_exclusions) != exclusion_guards or any(
            actual.get(name) != sql for name, sql in expected_exclusions.items()
        ):
            raise RecoveryRefused("protected_session_authority_unavailable")
        installed = set(actual) - exclusion_guards
        if not installed:
            # Full tables are installed on ordinary stores before any recovery
            # admission. Only positively empty authority tables may omit guards.
            if any(conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
                   for table in _LEDGER
                   if table not in {"recovery_store", "recovery_exclusions"}):
                raise RecoveryRefused("protected_session_authority_unavailable")
            return

        expected = {
            name: statement.replace(" IF NOT EXISTS", "", 1).encode("utf-8")
            for name, statement in _guard_statements(conn)
        }
        if (len(expected) != expected_count - len(exclusion_guards)
                or any(len(name.encode("utf-8")) > _MAX_GUARD_NAME_BYTES
                       or len(sql) > _MAX_GUARD_SQL_BYTES
                       for name, sql in expected.items())
                or installed != set(expected)
                or any(actual[name] != sql for name, sql in expected.items())):
            raise RecoveryRefused("protected_session_authority_unavailable")
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
