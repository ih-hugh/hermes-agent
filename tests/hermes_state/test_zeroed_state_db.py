"""#68474 hardening: zeroed state.db detection + quarantine."""

from __future__ import annotations

import pytest


def test_is_zeroed_state_db_and_quarantine(tmp_path):
    import hermes_state as hs

    db = tmp_path / "state.db"
    db.write_bytes(bytes(1024))
    assert hs.is_zeroed_state_db(db) is True

    q = hs.quarantine_invalid_state_db(db)
    assert q is not None
    assert q.exists()
    assert not db.exists()
    assert q.read_bytes() == bytes(1024)


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX only")
def test_is_zeroed_never_probes_special_files(tmp_path):
    """A FIFO at the state.db path must be rejected without any blocking read.

    Opening a FIFO for reading blocks until a writer appears; the zeroed
    probe must classify on file type alone (#98017 review, P2).
    """
    import os

    import hermes_state as hs
    from hermes_cli.backup import is_zeroed_sqlite_file

    fifo = tmp_path / "state.db"
    os.mkfifo(fifo)
    # Would hang forever before the regular-file guard if either probe
    # attempted open()+read on the FIFO.
    assert is_zeroed_sqlite_file(fifo) is False
    assert hs.is_zeroed_state_db(fifo) is False


def test_sessiondb_refuses_preexisting_zeroed_store_without_quarantine(tmp_path, monkeypatch):
    import hermes_state as hs
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = tmp_path / "state.db"
    db.write_bytes(bytes(4096))

    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        hs.SessionDB(db_path=db)
    assert db.read_bytes() == bytes(4096)
    assert not list(tmp_path.glob("state.db.zeroed-*.bak"))


def test_sessiondb_refuses_page_zero_clobber_before_open(tmp_path, monkeypatch):
    """Unknown prior authority keeps original bytes and sidecars untouched."""

    import hermes_state as hs
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = tmp_path / "state.db"
    clobbered = (b"bg_032237_0e4ce7A" * 256)[:4096]
    db.write_bytes(clobbered)
    (tmp_path / "state.db-wal").write_bytes(b"wal evidence")
    (tmp_path / "state.db-shm").write_bytes(b"shm evidence")

    assert hs.has_invalid_sqlite_header_preopen(db) is True
    assert hs.is_zeroed_state_db(db) is False

    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        hs.SessionDB(db_path=db)
    assert db.read_bytes() == clobbered
    assert (tmp_path / "state.db-wal").read_bytes() == b"wal evidence"
    assert (tmp_path / "state.db-shm").read_bytes() == b"shm evidence"
    assert not list(tmp_path.glob("state.db.notadb-*.bak"))


def test_is_zeroed_state_db_zero_byte_refusal(tmp_path, monkeypatch):
    """A pre-existing 0-byte file is not a newly created empty catalog."""
    import hermes_state as hs
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = tmp_path / "state.db"
    db.write_bytes(b"")  # 0-byte truncated file
    assert hs.is_zeroed_state_db(db) is True

    with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
        hs.SessionDB(db_path=db)
    assert db.exists() and db.stat().st_size == 0
    assert not list(tmp_path.glob("state.db.zeroed-*.bak"))


def test_concurrent_openers_refuse_unknown_zeroed_store(tmp_path):
    """Neither opener may replace an unclassifiable historical store."""
    import hermes_state as hs
    import threading
    from hermes_state_recovery import RecoveryRefused

    db = tmp_path / "state.db"
    db.write_bytes(bytes(4096))  # zeroed (all-NUL) 4 KB file

    errors: list = [None, None]

    def worker(idx):
        try:
            sdb = hs.SessionDB(db_path=db)
            sdb.close()
        except Exception as exc:
            errors[idx] = exc

    t1 = threading.Thread(target=worker, args=(0,))
    t2 = threading.Thread(target=worker, args=(1,))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert all(isinstance(error, RecoveryRefused) and
               error.code == "protected_session_authority_unavailable" for error in errors)
    assert db.read_bytes() == bytes(4096)
    assert not list(tmp_path.glob("state.db.zeroed-*.bak"))


def test_quarantine_fails_closed_when_lock_held(tmp_path):
    """#68805 review: when the cross-process lock cannot be acquired within
    the timeout, quarantine must FAIL CLOSED — return None without moving
    the file. A fail-open fallback would let a slow/paused startup that
    still owns the lock race with the fallback's re-check + rename.
    """
    import hermes_state as hs
    import platform
    import threading

    db = tmp_path / "state.db"
    db.write_bytes(bytes(4096))  # zeroed (all-NUL) 4 KB file

    lock_path = db.with_name(db.name + ".quarantine.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    # Hold the cross-process lock from a background thread so the main
    # thread's quarantine attempt cannot acquire it.
    lock_held = threading.Event()
    release_lock = threading.Event()

    def hold_lock():
        handle = lock_path.open("a+b")
        try:
            if platform.system() == "Windows":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_held.set()
            release_lock.wait(timeout=15)
            if platform.system() == "Windows":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            lock_held.clear()
        finally:
            handle.close()

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert lock_held.wait(timeout=5), "Background thread failed to acquire lock"

    # Reduce the quarantine lock timeout to keep the test fast. We patch
    # the deadline by calling quarantine directly — it uses a 5s timeout,
    # but we only need to verify it returns None without moving the file.
    result = hs.quarantine_invalid_state_db(db)

    # Must fail closed: return None without moving the zeroed file
    assert result is None, (
        f"quarantine_invalid_state_db returned {result} — expected None "
        f"(fail-closed when lock is held)"
    )
    assert db.exists(), "Zeroed state.db was moved despite lock being held"
    assert hs.is_zeroed_state_db(db), "File should still be zeroed (not moved)"

    # Release the lock so the background thread can exit cleanly
    release_lock.set()
    holder.join(timeout=5)


def test_concurrent_openers_zero_byte_startup_serialization(tmp_path, monkeypatch):
    """#97580: Verify that two concurrent SessionDB openers on a non-existent
    database serialize through the startup lock, avoid racing on the initial
    0-byte creation window, and do not falsely quarantine each other's live file.
    """
    import hermes_state as hs
    import threading
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = tmp_path / "state.db"

    errors = [None, None]
    results = [None, None]

    def worker(idx):
        try:
            sdb = hs.SessionDB(db_path=db)
            try:
                # Confirm schema is active
                row = sdb._conn.execute("SELECT 1").fetchone()
                assert row[0] == 1
                results[idx] = "ok"
            finally:
                sdb.close()
        except Exception as exc:
            errors[idx] = exc

    t1 = threading.Thread(target=worker, args=(0,))
    t2 = threading.Thread(target=worker, args=(1,))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert results.count("ok") >= 1
    assert all(error is None or (isinstance(error, RecoveryRefused) and
               error.code == "protected_session_authority_unavailable") for error in errors)
    # An opener seeing the first initializer's temporary empty inode may
    # refuse; after its commit the same ordinary opener can retry.
    retry = hs.SessionDB(db_path=db)
    retry.close()

    # No spurious quarantine backups should have been created
    backups = list(tmp_path.glob("state.db.zeroed-*.bak"))
    assert len(backups) == 0, f"Expected 0 quarantine backups, got: {backups}"
    assert db.exists()
    assert not hs.is_zeroed_state_db(db)


def test_live_connection_0_byte_is_not_sufficient_authority_proof(tmp_path, monkeypatch):
    """A tracked connection prevents quarantine, but not authority refusal."""
    import hermes_state as hs
    from hermes_cli.sqlite_safe_read import connect_tracked
    from hermes_state_recovery import RecoveryRefused

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db = tmp_path / "state.db"

    # Create a live tracked 0-byte connection
    conn = connect_tracked(str(db))
    try:
        assert db.exists() and db.stat().st_size == 0
        # is_zeroed_state_db must recognize the live connection and refuse to declare it zeroed
        assert hs.is_zeroed_state_db(db) is False

        with pytest.raises(RecoveryRefused, match="protected_session_authority_unavailable"):
            hs.SessionDB(db_path=db)
        assert db.stat().st_size == 0
        assert not list(tmp_path.glob("state.db.zeroed-*.bak"))

        # The original connection can still write safely
        conn.execute("CREATE TABLE live_check (id INTEGER)")
        conn.commit()
    finally:
        conn.close()
