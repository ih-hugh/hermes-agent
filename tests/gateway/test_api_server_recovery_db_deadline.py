"""The recovery worker's SessionDB cache lookup cannot wait past its deadline."""

from __future__ import annotations

import threading
import time

import pytest

from gateway.platforms.api_server import APIServerAdapter
from hermes_state_recovery_deadline import RecoveryDeadlineExceeded, recovery_deadline


def test_recovery_cache_lock_wait_refuses_before_registry_acquire(tmp_path) -> None:
    adapter = object.__new__(APIServerAdapter)
    adapter._session_db_cache_lock = threading.Lock()
    adapter._session_db_cache_closed = False
    adapter._session_dbs = {}
    home = tmp_path / "profile"
    home.mkdir()
    entered = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with adapter._session_db_cache_lock:
            entered.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold)
    thread.start()
    assert entered.wait(timeout=1)
    acquired = None
    try:
        began = time.monotonic()
        with recovery_deadline(time.monotonic() + 0.03):
            with pytest.raises(RecoveryDeadlineExceeded):
                acquired = adapter._open_and_cache_session_db(home)
        assert time.monotonic() - began < 0.5
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(timeout=1)
        if acquired is not None:
            adapter._close_cached_session_dbs()
    assert not thread.is_alive()
    assert adapter._session_dbs == {}
    assert not (home / "state.db").exists()
