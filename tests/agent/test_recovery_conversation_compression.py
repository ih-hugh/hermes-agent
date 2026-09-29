"""Compression claims a continuation before adopting or publishing it."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from agent import conversation_compression as compression
from hermes_state import SessionDB


def _rotated_db(tmp_path):
    db = SessionDB(tmp_path / "state.db")
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
    return db


def test_adoption_claims_child_before_agent_switch(tmp_path, monkeypatch):
    db = _rotated_db(tmp_path)
    monkeypatch.setattr(compression, "_rebind_session_context", lambda *_: None)
    agent = SimpleNamespace(
        session_id="parent",
        context_compressor=SimpleNamespace(),
        _memory_manager=None,
        platform="webui",
        _gateway_session_key=None,
    )
    try:
        recovered = compression._adopt_live_compression_child(agent, db, "parent")
        assert recovered
        assert agent.session_id == "child"
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions "
                "WHERE kind='ordinary_session' AND session_id='child'"
            ).fetchone() == (1,)
    finally:
        db.close()


def test_new_child_claim_precedes_publish(tmp_path, monkeypatch):
    db = SessionDB(tmp_path / "state.db")
    db.create_session("parent", source="webui")
    monkeypatch.setattr(compression, "mint_session_id", lambda: "new-child")

    def assert_claimed(**_kwargs):
        with sqlite3.connect(db.db_path) as raw:
            assert raw.execute(
                "SELECT 1 FROM recovery_exclusions "
                "WHERE kind='ordinary_session' AND session_id='new-child'"
            ).fetchone() == (1,)
        raise RuntimeError("stopped-at-publish")

    monkeypatch.setattr(db, "publish_compression_child", assert_claimed)
    agent = SimpleNamespace(
        session_id="parent",
        _session_db=db,
        platform="webui",
        model="test",
        _session_init_model_config={},
        working_directory=None,
        _flush_messages_to_session_db=lambda *_args, **_kwargs: None,
    )
    lease = SimpleNamespace(holder=None, watermark=None, ttl=60)
    try:
        with pytest.raises(RuntimeError, match="stopped-at-publish"):
            compression._publish_rotated_compaction(
                agent,
                [],
                [{"role": "user", "content": "summary"}],
                new_system_prompt="summary",
                lease=lease,
                old_session_id="parent",
                compressed_user_turn_outcome="none",
            )
    finally:
        db.close()
