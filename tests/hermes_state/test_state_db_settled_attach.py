"""A settled ordinary store attaches without claiming or reconciling its schema."""

from __future__ import annotations

import sqlite3
import os
import stat
from pathlib import Path

import pytest

import hermes_state
import hermes_state_recovery_exclusions as exclusions
import hermes_state_wal
from hermes_state import SessionDB
from hermes_state_recovery_guard import install_recovery_guards
from hermes_state_recovery import RecoveryRefused


def _settled(path: Path) -> None:
    # The first fresh open creates FTS; the next existing open records its
    # layout marker. Only a fully initialized ordinary store gets the stamp.
    SessionDB(path).close()
    with sqlite3.connect(path) as conn:
        assert (
            conn.execute(
                "SELECT value FROM state_meta WHERE key='ordinary_init_settled_v1'"
            ).fetchone()
            is None
        )
    SessionDB(path).close()
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT value FROM state_meta WHERE key='fts_storage_version'"
        ).fetchone() == ("2",)
        assert (
            conn.execute(
                "SELECT value FROM state_meta WHERE key='ordinary_init_settled_v1'"
            ).fetchone()
            is not None
        )
        assert (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'recovery_guard_*' "
                "AND name NOT GLOB 'recovery_guard_recovery_exclusions_*' LIMIT 1"
            ).fetchone()
            is None
        )


def _raw_claims(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    calls: list[Path] = []
    original = exclusions.begin_raw_schema_claim

    def claimed(path: Path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(exclusions, "begin_raw_schema_claim", claimed)
    return calls


def test_current_ordinary_catalog_attaches_without_a_raw_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == []


def test_deleted_wal_refusal_precedes_any_catalog_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    calls: list[str] = []

    def refuse(_path: Path) -> None:
        calls.append("refuse")
        raise RuntimeError("deleted WAL generation")

    def forbidden_connect(*_args, **_kwargs):
        calls.append("connect")
        pytest.fail("SQLite opened after deleted-generation refusal")

    monkeypatch.setattr(
        hermes_state, "_close_time_checkpoint_configurable", lambda: True
    )
    monkeypatch.setattr(hermes_state, "refuse_deleted_wal_generation", refuse)
    monkeypatch.setattr(sqlite3, "connect", forbidden_connect)
    with pytest.raises(RuntimeError, match="deleted WAL generation"):
        SessionDB(path)
    assert calls == ["refuse"]


def test_fast_wal_attach_restores_connection_durability_companions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    called: list[str] = []
    original = hermes_state_wal._apply_wal_companions

    def companions(conn: sqlite3.Connection) -> None:
        called.append("wal")
        original(conn)

    monkeypatch.setattr(hermes_state_wal, "_apply_wal_companions", companions)
    claims = _raw_claims(monkeypatch)
    db = SessionDB(path)
    try:
        assert claims == []
        assert called == ["wal"]
        with db._lock:
            assert (
                db._conn.execute("PRAGMA journal_size_limit").fetchone()[0]
                == 64 * 1024 * 1024
            )
            if os.sys.platform == "darwin":
                assert db._conn.execute("PRAGMA synchronous").fetchone()[0] >= 2
    finally:
        db.close()


@pytest.mark.parametrize(
    ("sql", "restored"),
    [
        ("DELETE FROM state_meta WHERE key='ordinary_init_settled_v1'", None),
        (
            "DELETE FROM state_meta WHERE key='fts_storage_version'",
            "fts_storage_version",
        ),
        (
            "DELETE FROM state_meta WHERE key='fts_tool_full_content_high_water'",
            "fts_tool_full_content_high_water",
        ),
        ("UPDATE schema_version SET version=29", "schema_version"),
        ("DROP INDEX idx_messages_platform_msg_id", "idx_messages_platform_msg_id"),
        ("DROP TABLE gateway_routing", "gateway_routing"),
        ("DROP TRIGGER messages_fts_update", "messages_fts_update"),
    ],
)
def test_drift_reconciles_under_raw_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sql: str,
    restored: str | None,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        conn.execute(sql)
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == [path]
    if restored is not None:
        with sqlite3.connect(path) as conn:
            if restored == "schema_version":
                assert conn.execute(
                    "SELECT version FROM schema_version"
                ).fetchone() == (30,)
            elif restored in {
                "gateway_routing",
                "idx_messages_platform_msg_id",
                "messages_fts_update",
            }:
                assert (
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE name=?", (restored,)
                    ).fetchone()
                    is not None
                )
            else:
                assert (
                    conn.execute(
                        "SELECT 1 FROM state_meta WHERE key=?", (restored,)
                    ).fetchone()
                    is not None
                )


def test_loaded_initializer_source_drift_cannot_mint_new_stamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        before = conn.execute(
            "SELECT value FROM state_meta WHERE key='ordinary_init_settled_v1'"
        ).fetchone()
    claims = _raw_claims(monkeypatch)
    monkeypatch.setattr(hermes_state, "_read_init_source_epoch", lambda: "0" * 64)
    SessionDB(path).close()
    assert claims == [path]
    with sqlite3.connect(path) as conn:
        assert (
            conn.execute(
                "SELECT value FROM state_meta WHERE key='ordinary_init_settled_v1'"
            ).fetchone()
            == before
        )


def test_configured_wal_rechecks_external_delete_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    monkeypatch.setattr(hermes_state_wal, "resolve_journal_mode", lambda: "delete")
    _settled(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    monkeypatch.setattr(hermes_state_wal, "resolve_journal_mode", lambda: "wal")
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == [path]
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_pending_fts_and_raw_claim_invalidate_fast_hint(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO state_meta(key,value) VALUES('fts_rebuild_high_water','1')"
        )
    assert hermes_state._inspect_settled_ordinary_store(path) is None
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM state_meta WHERE key='fts_rebuild_high_water'")
    lease = exclusions.begin_raw_schema_claim(path)
    try:
        assert hermes_state._inspect_settled_ordinary_store(path) is None
    finally:
        exclusions.finish_raw_schema_claim(lease)


def test_cjk_capability_mismatch_and_bounded_stamp_invalidate_hint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        present = (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='messages_fts_cjk'"
            ).fetchone()
            is not None
        )
        assert not hermes_state._settled_ordinary_stamp_valid(
            conn,
            cjk_loaded=not present,
        )
        conn.execute(
            "UPDATE state_meta SET value=? WHERE key='ordinary_init_settled_v1'",
            ("x" * 200,),
        )
    assert hermes_state._inspect_settled_ordinary_store(path) is None


def test_partial_fts_trigger_refuses_even_with_matching_schema_cookie(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        stamp = conn.execute(
            "SELECT value FROM state_meta WHERE key='ordinary_init_settled_v1'"
        ).fetchone()[0]
        conn.execute("DROP TRIGGER messages_fts_update")
        cookie = conn.execute("PRAGMA schema_version").fetchone()[0]
        parts = stamp.split(":")
        parts[3] = str(cookie)
        conn.execute(
            "UPDATE state_meta SET value=? WHERE key='ordinary_init_settled_v1'",
            (":".join(parts),),
        )
    assert hermes_state._inspect_settled_ordinary_store(path) is None


def test_guarded_full_catalog_never_uses_ordinary_fast_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        install_recovery_guards(conn)
    assert hermes_state._inspect_settled_ordinary_store(path) is None
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == []


def test_guarded_claim_refusal_does_not_chmod_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        install_recovery_guards(conn)
    os.chmod(path, 0o644)
    before = path.read_bytes()
    with pytest.raises(RecoveryRefused):
        exclusions.begin_raw_schema_claim(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert path.read_bytes() == before


def test_unknown_catalog_refuses_before_file_hardening(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE recovery_unrecognized (id TEXT)")
    os.chmod(path, 0o644)
    before = path.read_bytes()
    with pytest.raises(RecoveryRefused):
        exclusions.begin_raw_schema_claim(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert path.read_bytes() == before


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_source_epoch_refuses_fifo_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "source.py"
    os.mkfifo(path)
    monkeypatch.setattr(hermes_state, "__file__", str(tmp_path / "hermes_state.py"))
    monkeypatch.setattr(hermes_state, "_INIT_SOURCE_FILES", ("source.py",))
    assert hermes_state._read_init_source_epoch() is None


def test_oversized_or_non_uuid_store_identity_is_not_a_fast_hint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE recovery_store SET store_id=? WHERE singleton=1", ("x" * 100_000,)
        )
    with pytest.raises(RecoveryRefused):
        hermes_state._inspect_settled_ordinary_store(path)


def test_legacy_routing_primary_key_is_reconciled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE gateway_routing")
        conn.execute(
            "CREATE TABLE gateway_routing (scope TEXT NOT NULL DEFAULT '', "
            "session_key TEXT PRIMARY KEY, entry_json TEXT NOT NULL, updated_at REAL NOT NULL)"
        )
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == [path]
    with sqlite3.connect(path) as conn:
        pk = [
            (row[1], row[5])
            for row in conn.execute("PRAGMA table_info(gateway_routing)")
            if row[5]
        ]
    assert pk == [("scope", 1), ("session_key", 2)]


def test_legacy_null_active_row_is_reconciled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.db"
    _settled(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO sessions(id,source,started_at) VALUES('legacy','cli',1.0)"
        )
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='messages'"
        ).fetchone()[0]
        assert "active INTEGER NOT NULL DEFAULT 1" in ddl
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute(
            "UPDATE sqlite_master SET sql=? WHERE name='messages'",
            (
                ddl.replace(
                    "active INTEGER NOT NULL DEFAULT 1", "active INTEGER DEFAULT 1"
                ),
            ),
        )
        conn.execute("PRAGMA writable_schema=OFF")
        cookie = conn.execute("PRAGMA schema_version").fetchone()[0]
        conn.execute(f"PRAGMA schema_version={cookie + 1}")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO messages(session_id,role,content,timestamp,active) "
            "VALUES('legacy','user','visible after heal',1.0,NULL)"
        )
    claims = _raw_claims(monkeypatch)
    SessionDB(path).close()
    assert claims == [path]
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT active FROM messages WHERE session_id='legacy'"
        ).fetchone() == (1,)


def test_writer_connection_revalidates_actual_store_after_path_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.db"
    other = tmp_path / "other.db"
    _settled(first)
    _settled(other)
    with sqlite3.connect(first) as conn:
        first_id = conn.execute(
            "SELECT store_id FROM recovery_store WHERE singleton=1"
        ).fetchone()[0]
    with sqlite3.connect(other) as conn:
        other_id = conn.execute(
            "SELECT store_id FROM recovery_store WHERE singleton=1"
        ).fetchone()[0]
    assert first_id != other_id
    real_connect = hermes_state._connect_tracked_db
    hidden = tmp_path / "hidden.db"

    def substituted(*args, **kwargs):
        if "mode=rw" not in str(args[0]) or "first.db" not in str(args[0]):
            return real_connect(*args, **kwargs)
        first.rename(hidden)
        other.rename(first)
        try:
            return real_connect(*args, **kwargs)
        finally:
            first.rename(other)
            hidden.rename(first)

    monkeypatch.setattr(hermes_state, "_connect_tracked_db", substituted)
    with pytest.raises(RecoveryRefused):
        SessionDB(first)
    with sqlite3.connect(first) as conn:
        assert (
            conn.execute(
                "SELECT store_id FROM recovery_store WHERE singleton=1"
            ).fetchone()[0]
            == first_id
        )
    with sqlite3.connect(other) as conn:
        assert (
            conn.execute(
                "SELECT store_id FROM recovery_store WHERE singleton=1"
            ).fetchone()[0]
            == other_id
        )
