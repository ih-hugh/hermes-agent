"""A stale ordinary writer claims a compression tip before adopting it."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from agent.session_persistence import _db_flush_adopt_compression_tip
from hermes_state import SessionDB


def test_flush_claims_live_tip_before_adoption(tmp_path):
    db = SessionDB(tmp_path / "state.db")
    try:
        db.create_session("parent", source="webui")
        db.append_message("parent", "user", "original")
        assert db.try_acquire_compression_lock("parent", "winner", ttl_seconds=60)
        db.publish_compression_child(
            parent_session_id="parent",
            child_session_id="child",
            source="webui",
            messages=[{"role": "user", "content": "summary"}],
            compression_lock_holder="winner",
        )
        agent = SimpleNamespace(
            session_id="parent",
            _session_db=db,
            _flushed_db_message_ids={1},
            _last_flushed_db_idx=1,
            _compression_adoption_failed=True,
        )
        assert _db_flush_adopt_compression_tip(agent)
        assert agent.session_id == "child"
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions "
                "WHERE kind='ordinary_session' AND session_id='child'"
            ).fetchone() == (1,)
    finally:
        db.close()
