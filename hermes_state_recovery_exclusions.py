"""Durable first-admission exclusions on the selected state.db.

The exact claim and protected root use one SQLite writer domain. Ordinary
claims are permanent; only a process-owned raw-schema lease can be released.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import threading
import uuid
import weakref
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Never, SupportsIndex

from hermes_state_recovery import RecoveryRefused

if TYPE_CHECKING:
    from agent.recovery_context import WritePermit
    from agent.recovery_producers import ProducerLease, ProducerRegistry
    from hermes_state import SessionDB


EXCLUSION_TABLE = "recovery_exclusions"
EXCLUSION_SQL = (
    "CREATE TABLE IF NOT EXISTS recovery_exclusions ("
    "claim_id TEXT PRIMARY KEY,"
    "kind TEXT NOT NULL CHECK(kind IN ('ordinary_session','unscoped_ordinary','raw_schema')) ,"
    "session_id TEXT UNIQUE,"
    "CHECK ((kind='ordinary_session' AND session_id IS NOT NULL AND length(session_id) BETWEEN 1 AND 255) "
    "OR (kind IN ('unscoped_ordinary','raw_schema') AND session_id IS NULL))"
    ")",
    "CREATE TRIGGER IF NOT EXISTS recovery_guard_recovery_exclusions_insert "
    "BEFORE INSERT ON recovery_exclusions BEGIN "
    "SELECT CASE WHEN recovery_exclusion_claim_guard('insert',NEW.claim_id,NEW.kind,NEW.session_id)=1 "
    "THEN NULL ELSE RAISE(ABORT,'recovery exclusion write refused') END; END",
    "CREATE TRIGGER IF NOT EXISTS recovery_guard_recovery_exclusions_update "
    "BEFORE UPDATE ON recovery_exclusions BEGIN "
    "SELECT RAISE(ABORT,'recovery exclusion update refused'); END",
    "CREATE TRIGGER IF NOT EXISTS recovery_guard_recovery_exclusions_delete "
    "BEFORE DELETE ON recovery_exclusions BEGIN "
    "SELECT CASE WHEN recovery_exclusion_claim_guard('delete',OLD.claim_id,OLD.kind,OLD.session_id)=1 "
    "THEN NULL ELSE RAISE(ABORT,'recovery exclusion write refused') END; END",
)
EXCLUSION_NAMES = frozenset((
    EXCLUSION_TABLE,
    "recovery_guard_recovery_exclusions_insert",
    "recovery_guard_recovery_exclusions_update",
    "recovery_guard_recovery_exclusions_delete",
))
_ISSUER = object()
_NONCE = uuid.uuid4().hex
_LOCK = threading.Lock()
_RAW_LEASES: weakref.WeakKeyDictionary[RawSchemaLease, tuple[int, str, Path, str, int, int]] = (
    weakref.WeakKeyDictionary()
)


@dataclass(frozen=True, slots=True)
class OrdinaryClaimReceipt:
    path: Path
    session_ids: tuple[str, ...]
    unscoped: bool = False


class RawSchemaLease:
    """Opaque process-owned right to release only one successful initializer."""

    __slots__ = ("__weakref__", "_claim_id")

    def __init__(self, issuer: object, claim_id: str):
        if issuer is not _ISSUER:
            raise TypeError("raw schema leases are issued internally")
        self._claim_id = claim_id

    def __reduce_ex__(self, protocol: SupportsIndex, /) -> Never:
        raise TypeError("raw schema leases cannot be serialized")


def install_exclusion_schema(conn: sqlite3.Connection) -> None:
    """Run each canonical DDL statement without executescript's implicit commit."""
    for statement in EXCLUSION_SQL:
        conn.execute(statement)


def _canonical_exclusion_shape(conn: sqlite3.Connection) -> bool:
    names = tuple(EXCLUSION_NAMES)
    max_sql = max(len(statement.encode("utf-8")) for statement in EXCLUSION_SQL)
    metadata = conn.execute(
        "SELECT length(CAST(name AS BLOB)),length(CAST(sql AS BLOB)) "
        "FROM sqlite_master WHERE name IN (?,?,?,?) LIMIT 5",
        names,
    ).fetchall()
    if (len(metadata) != len(EXCLUSION_SQL)
            or any(type(name_size) is not int or not 0 < name_size <= 128
                   or type(sql_size) is not int or not 0 < sql_size <= max_sql
                   for name_size, sql_size in metadata)):
        return False
    rows = conn.execute(
        "SELECT name,substr(CAST(sql AS BLOB),1,?) "
        "FROM sqlite_master WHERE name IN (?,?,?,?) LIMIT 5",
        (max_sql + 1, *names),
    ).fetchall()
    if len(rows) != len(EXCLUSION_SQL):
        return False
    expected = {
        "recovery_exclusions": EXCLUSION_SQL[0].replace(" IF NOT EXISTS", "", 1),
        "recovery_guard_recovery_exclusions_insert": EXCLUSION_SQL[1].replace(" IF NOT EXISTS", "", 1),
        "recovery_guard_recovery_exclusions_update": EXCLUSION_SQL[2].replace(" IF NOT EXISTS", "", 1),
        "recovery_guard_recovery_exclusions_delete": EXCLUSION_SQL[3].replace(" IF NOT EXISTS", "", 1),
    }
    return all(type(sql) is bytes and expected.get(name, "").encode("utf-8") == sql
               for name, sql in rows)


def _catalog(conn: sqlite3.Connection) -> Literal["absent", "bootstrap", "old_ordinary", "full"]:
    """Classify only recognized authority shapes; never infer absence on error."""
    from hermes_state_recovery_guard import _LEDGER, _ROWS

    max_entries = len(_LEDGER) + 3 * (len(_ROWS) + len(_LEDGER))
    metadata = conn.execute(
        "SELECT length(CAST(type AS BLOB)),length(CAST(name AS BLOB)) "
        "FROM sqlite_master WHERE name GLOB 'recovery_*' LIMIT ?",
        (max_entries + 1,),
    ).fetchall()
    if (len(metadata) > max_entries or any(
        type(type_size) is not int or not 0 < type_size <= 8
        or type(name_size) is not int or not 0 < name_size <= 128
        for type_size, name_size in metadata
    )):
        raise RecoveryRefused("protected_session_authority_unavailable")
    raw_rows = conn.execute(
        "SELECT type,substr(CAST(name AS BLOB),1,129) "
        "FROM sqlite_master WHERE name GLOB 'recovery_*' LIMIT ?",
        (max_entries + 1,),
    ).fetchall()
    if len(raw_rows) != len(metadata):
        raise RecoveryRefused("protected_session_authority_unavailable")
    try:
        rows = [(kind, raw_name.decode("utf-8")) for kind, raw_name in raw_rows
                if type(raw_name) is bytes and len(raw_name) <= 128]
    except UnicodeError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    if len(rows) != len(raw_rows):
        raise RecoveryRefused("protected_session_authority_unavailable")
    names = {name for _kind, name in rows}
    if not names:
        return "absent"
    if names == EXCLUSION_NAMES:
        if not _canonical_exclusion_shape(conn):
            raise RecoveryRefused("protected_session_authority_unavailable")
        return "bootstrap"
    table_names = {name for kind, name in rows if kind == "table"}
    non_tables = {name for kind, name in rows if kind != "table"}
    old_tables = set(_LEDGER) - {EXCLUSION_TABLE}
    if table_names == old_tables and not non_tables:
        # The immediately prior reviewed schema had these authority tables but
        # no protected rows or guards. Upgrade it only when every column shape
        # is present; a protected or partial older store must refuse.
        from hermes_recovery_refusal import _REQUIRED_COLUMNS

        for table in old_tables:
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            if not _REQUIRED_COLUMNS[table] <= columns:
                raise RecoveryRefused("protected_session_authority_unavailable")
        if any(conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
               for table in old_tables - {"recovery_store"}):
            raise RecoveryRefused("protected_session_authority_unavailable")
        return "old_ordinary"
    if EXCLUSION_TABLE not in table_names or not _canonical_exclusion_shape(conn):
        raise RecoveryRefused("protected_session_authority_unavailable")
    from hermes_recovery_refusal import require_compatible_recovery_connection
    from hermes_state_recovery_guard import require_current_recovery_guards

    require_compatible_recovery_connection(conn)
    require_current_recovery_guards(conn)
    return "full"


def _protected_exists(conn: sqlite3.Connection, catalog: str) -> bool:
    if catalog != "full":
        return False
    row = conn.execute("SELECT 1 FROM recovery_sessions LIMIT 1").fetchone()
    member = conn.execute("SELECT 1 FROM recovery_members LIMIT 1").fetchone()
    guard = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' "
        "AND name GLOB 'recovery_guard_*' AND name NOT IN (?,?,?) LIMIT 1",
        ("recovery_guard_recovery_exclusions_insert",
         "recovery_guard_recovery_exclusions_update",
         "recovery_guard_recovery_exclusions_delete"),
    ).fetchone()
    return row is not None or member is not None or guard is not None


def existing_protected_store(path: Path) -> bool:
    """Read-only branch hint; claim/reserve recheck under BEGIN IMMEDIATE."""
    return inspect_protected_store(path) is not None


def inspect_protected_store(path: Path) -> tuple[tuple[int, int], str] | None:
    """Capture a protected store's file and persistent identity in one observation."""
    try:
        identity = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    if not stat.S_ISREG(identity.st_mode):
        raise RecoveryRefused("protected_session_authority_unavailable")
    from hermes_state import has_invalid_sqlite_header_preopen

    if has_invalid_sqlite_header_preopen(path):
        raise RecoveryRefused("protected_session_authority_unavailable")
    try:
        with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)) as conn:
            conn.execute("PRAGMA query_only=ON")
            if not _protected_exists(conn, _catalog(conn)):
                return None
            row = conn.execute(
                "SELECT store_id FROM recovery_store WHERE singleton=1"
            ).fetchone()
            current = path.lstat()
            if (row is None or type(row[0]) is not str or not row[0]
                    or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)):
                raise RecoveryRefused("protected_session_authority_unavailable")
            return (identity.st_dev, identity.st_ino), row[0]
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    except OSError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc


def _connect(path: Path) -> sqlite3.Connection:
    from hermes_state import _secure_state_db_files, has_invalid_sqlite_header_preopen

    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL distinguishes our new empty inode from a pre-existing zero-byte
    # state.db. SQLite accepts the latter as an empty catalog, but its previous
    # authority is unknowable and must not be replaced by bootstrap DDL.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        try:
            identity = path.lstat()
        except OSError as exc:
            raise RecoveryRefused("protected_session_authority_unavailable") from exc
        if not stat.S_ISREG(identity.st_mode) or identity.st_size == 0:
            raise RecoveryRefused("protected_session_authority_unavailable")
        if has_invalid_sqlite_header_preopen(path):
            raise RecoveryRefused("protected_session_authority_unavailable")
    else:
        try:
            identity = os.fstat(fd)
        finally:
            os.close(fd)
    _secure_state_db_files(path)
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    try:
        current = path.lstat()
        if ((current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                or not stat.S_ISREG(current.st_mode)):
            raise RecoveryRefused("protected_session_authority_unavailable")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except BaseException:
        conn.close()
        raise


def _authorize_one(conn: sqlite3.Connection, operation: str, claim_id: str,
                   kind: str, session_id: str | None) -> None:
    used = False

    def guard(actual_operation, actual_id, actual_kind, actual_session):
        nonlocal used
        if (used or (actual_operation, actual_id, actual_kind, actual_session)
                != (operation, claim_id, kind, session_id)):
            return 0
        used = True
        return 1

    conn.create_function("recovery_exclusion_claim_guard", 4, guard)


def _claim(path: Path, kind: Literal["ordinary_session", "unscoped_ordinary", "raw_schema"],
           session_ids: tuple[str, ...] = ()) -> str | None:
    try:
        with closing(_connect(path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                catalog = _catalog(conn)
                if kind in {"unscoped_ordinary", "raw_schema"} and _protected_exists(conn, catalog):
                    raise RecoveryRefused("protected_session_dispatch")
                if kind == "ordinary_session" and catalog == "full":
                    for sid in session_ids:
                        if conn.execute(
                            "SELECT 1 FROM recovery_sessions WHERE session_id=? LIMIT 1",
                            (sid,)).fetchone() is not None or conn.execute(
                            "SELECT 1 FROM recovery_members WHERE session_id=? LIMIT 1",
                            (sid,)).fetchone() is not None:
                            raise RecoveryRefused("protected_session_dispatch")
                if catalog in {"absent", "old_ordinary"}:
                    install_exclusion_schema(conn)
                if kind == "ordinary_session":
                    for sid in session_ids:
                        claim_id = "ordinary:" + hashlib.sha256(sid.encode("utf-8")).hexdigest()
                        existing = conn.execute(
                            "SELECT kind,session_id FROM recovery_exclusions WHERE claim_id=? OR session_id=?",
                            (claim_id, sid)).fetchone()
                        if existing is not None:
                            if tuple(existing) != (kind, sid):
                                raise RecoveryRefused("exclusion_conflict")
                            continue
                        _authorize_one(conn, "insert", claim_id, kind, sid)
                        conn.execute(
                            "INSERT INTO recovery_exclusions(claim_id,kind,session_id) VALUES(?,?,?)",
                            (claim_id, kind, sid))
                    result = None
                else:
                    claim_id = ("unscoped_ordinary" if kind == "unscoped_ordinary"
                                else "raw:" + uuid.uuid4().hex)
                    if kind == "unscoped_ordinary" and conn.execute(
                            "SELECT 1 FROM recovery_exclusions WHERE claim_id=?",
                            (claim_id,)).fetchone() is not None:
                        result = None
                    else:
                        _authorize_one(conn, "insert", claim_id, kind, None)
                        conn.execute(
                            "INSERT INTO recovery_exclusions(claim_id,kind,session_id) VALUES(?,?,NULL)",
                            (claim_id, kind))
                        result = claim_id if kind == "raw_schema" else None
                conn.commit()
                return result
            except BaseException:
                conn.rollback()
                raise
    except RecoveryRefused:
        raise
    except (sqlite3.DatabaseError, OSError) as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc


def claim_ordinary_sessions(path: Path, session_ids: tuple[str, ...]) -> OrdinaryClaimReceipt:
    if (not isinstance(path, Path) or type(session_ids) is not tuple or not session_ids
            or any(type(sid) is not str or not 1 <= len(sid) <= 255 for sid in session_ids)):
        raise RecoveryRefused("invalid_ordinary_identity")
    exact = tuple(dict.fromkeys(session_ids))
    _claim(path, "ordinary_session", exact)
    return OrdinaryClaimReceipt(path, exact)


def claim_unscoped_ordinary(path: Path) -> OrdinaryClaimReceipt:
    if not isinstance(path, Path):
        raise RecoveryRefused("invalid_ordinary_identity")
    _claim(path, "unscoped_ordinary")
    return OrdinaryClaimReceipt(path, (), unscoped=True)


def begin_raw_schema_claim(path: Path) -> RawSchemaLease:
    if not isinstance(path, Path):
        raise RecoveryRefused("invalid_ordinary_identity")
    claim_id = _claim(path, "raw_schema")
    if claim_id is None:
        raise RecoveryRefused("protected_session_authority_unavailable")
    lease = RawSchemaLease(_ISSUER, claim_id)
    identity = path.stat()
    with _LOCK:
        _RAW_LEASES[lease] = (
            os.getpid(), _NONCE, path.resolve(), claim_id, identity.st_dev, identity.st_ino,
        )
    return lease


def assert_raw_schema_lease_target(lease: RawSchemaLease,
                                   *, conn: sqlite3.Connection | None = None) -> Path:
    """Refuse a moved or unreadable claimed file before any initializer effect."""
    if type(lease) is not RawSchemaLease:
        raise RecoveryRefused("invalid_raw_schema_lease")
    with _LOCK:
        record = _RAW_LEASES.get(lease)
    if record is None or record[:2] != (os.getpid(), _NONCE):
        raise RecoveryRefused("invalid_raw_schema_lease")
    _, _, path, claim_id, device, inode = record
    try:
        identity = path.lstat()
        if (not stat.S_ISREG(identity.st_mode)
                or (identity.st_dev, identity.st_ino) != (device, inode)):
            raise RecoveryRefused("invalid_raw_schema_lease")
        from hermes_state import has_invalid_sqlite_header_preopen

        if has_invalid_sqlite_header_preopen(path):
            raise RecoveryRefused("invalid_raw_schema_lease")
        if conn is not None:
            databases = conn.execute("PRAGMA database_list").fetchall()
            main = [row[2] for row in databases if row[1] == "main"]
            if len(main) != 1 or not main[0] or Path(main[0]).resolve() != path:
                raise RecoveryRefused("invalid_raw_schema_lease")
            if _catalog(conn) not in {"bootstrap", "full"}:
                raise RecoveryRefused("invalid_raw_schema_lease")
            row = conn.execute(
                "SELECT kind,session_id FROM recovery_exclusions WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
            if row is None or tuple(row) != ("raw_schema", None):
                raise RecoveryRefused("invalid_raw_schema_lease")
    except OSError as exc:
        raise RecoveryRefused("invalid_raw_schema_lease") from exc
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("invalid_raw_schema_lease") from exc
    return path


def finish_raw_schema_claim(lease: RawSchemaLease,
                            *, conn: sqlite3.Connection | None = None) -> None:
    assert_raw_schema_lease_target(lease, conn=conn)
    if type(lease) is not RawSchemaLease:
        raise RecoveryRefused("invalid_raw_schema_lease")
    with _LOCK:
        record = _RAW_LEASES.get(lease)
    if record is None or record[:2] != (os.getpid(), _NONCE):
        raise RecoveryRefused("invalid_raw_schema_lease")
    _, _, path, claim_id, device, inode = record
    try:
        identity = path.stat()
    except OSError as exc:
        raise RecoveryRefused("invalid_raw_schema_lease") from exc
    if (identity.st_dev, identity.st_ino) != (device, inode):
        raise RecoveryRefused("invalid_raw_schema_lease")
    if conn is not None:
        try:
            databases = conn.execute("PRAGMA database_list").fetchall()
        except sqlite3.DatabaseError as exc:
            raise RecoveryRefused("invalid_raw_schema_lease") from exc
        main = [row[2] for row in databases if row[1] == "main"]
        if len(main) != 1 or not main[0] or Path(main[0]).resolve() != path:
            raise RecoveryRefused("invalid_raw_schema_lease")
    def _finish(active: sqlite3.Connection) -> None:
        active.execute("BEGIN IMMEDIATE")
        try:
            if _catalog(active) not in {"bootstrap", "full"}:
                raise RecoveryRefused("protected_session_authority_unavailable")
            row = active.execute(
                "SELECT kind,session_id FROM recovery_exclusions WHERE claim_id=?",
                (claim_id,)).fetchone()
            if row is not None:
                if tuple(row) != ("raw_schema", None):
                    raise RecoveryRefused("invalid_raw_schema_lease")
                _authorize_one(active, "delete", claim_id, "raw_schema", None)
                active.execute("DELETE FROM recovery_exclusions WHERE claim_id=?", (claim_id,))
            active.commit()
        except BaseException:
            active.rollback()
            raise
    try:
        if conn is None:
            with closing(_connect(path)) as active:
                _finish(active)
        else:
            _finish(conn)
    except RecoveryRefused:
        raise
    except (sqlite3.DatabaseError, OSError) as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    with _LOCK:
        _RAW_LEASES.pop(lease, None)


def root_exclusion(conn: sqlite3.Connection, session_id: str) -> str | None:
    """Called only inside RecoveryStore's root BEGIN IMMEDIATE transaction."""
    if not _canonical_exclusion_shape(conn):
        return "exclusion_authority_unavailable"
    if conn.execute(
            "SELECT 1 FROM recovery_exclusions WHERE kind='ordinary_session' AND session_id=?",
            (session_id,)).fetchone() is not None:
        return "ordinary_session_claimed"
    if conn.execute(
            "SELECT 1 FROM recovery_exclusions WHERE kind='unscoped_ordinary' LIMIT 1"
    ).fetchone() is not None:
        return "unscoped_ordinary_claimed"
    if conn.execute(
            "SELECT 1 FROM recovery_exclusions WHERE kind='raw_schema' LIMIT 1"
    ).fetchone() is not None:
        return "raw_schema_active"
    return None


def authorize_or_claim_agent_construction(
    session_id: str,
    db_path: Path,
    session_db: SessionDB | None,
    registry: ProducerRegistry | None,
    lease: ProducerLease | None,
    write_permit: WritePermit | None,
) -> None:
    """Direct-constructor backstop before client/tool initialization effects.

    A protected identity needs its current process-owned member authority; every
    other identity commits an unconditional ordinary claim on the selected DB.
    """
    if (type(session_id) is not str or not 1 <= len(session_id) <= 255
            or not isinstance(db_path, Path)):
        raise RecoveryRefused("invalid_ordinary_identity")
    if session_db is None:
        claim_ordinary_sessions(db_path, (session_id,))
        return
    if (Path(session_db.db_path).resolve() != db_path.resolve()
            or session_db.read_only):
        raise RecoveryRefused("protected_session_authority_unavailable")
    try:
        members = session_db._read_all(
            "SELECT run_id,generation,profile,scope_digest,producer_state "
            "FROM recovery_members WHERE session_id=? LIMIT 3", (session_id,))
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    if not members:
        claim_ordinary_sessions(db_path, (session_id,))
        return
    if len(members) > 2:
        raise RecoveryRefused("protected_session_authority_unavailable")
    from agent.recovery_context import (
        current_write_permit, validate_producer_permit, validate_write_permit,
    )
    from agent.recovery_producers import current_lease, current_registry
    from hermes_state_recovery import RecoveryScope, RecoveryStore

    if (registry is None or registry is not current_registry()
            or lease is None
            or lease is not current_lease() or write_permit is not current_write_permit()
            or write_permit is None
            or registry.store.db is not session_db):
        raise RecoveryRefused("protected_session_dispatch")
    store = RecoveryStore(session_db)
    for run_id, generation, profile, digest, state in members:
        if state != "open":
            continue
        scope = RecoveryScope(store.store_id, profile, digest, session_id)
        if (registry.scope == scope and registry.run_id == run_id
                and registry.generation == generation
                and lease.registry is registry and lease._state == "running"
                and registry._leases.get(lease.producer_id) is lease
                and validate_producer_permit(registry.permit, store, scope, run_id, generation)
                and validate_write_permit(write_permit, store, scope, run_id, generation,
                                          mutation="session")):
            return
    raise RecoveryRefused("protected_session_dispatch")
