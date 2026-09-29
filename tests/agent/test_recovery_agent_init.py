"""Direct AIAgent initialization claims its exact identity before setup effects."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from agent import agent_init
from hermes_state import SessionDB
from hermes_state_recovery import RecoveryRefused
from tests.agent.test_recovery_runtime import _admitted


def test_protected_direct_construction_refuses_before_stdio_or_client(
    tmp_path, monkeypatch
):
    db, _store, scope, _registry = _admitted(tmp_path)
    monkeypatch.setattr(
        agent_init,
        "_install_safe_stdio",
        lambda: pytest.fail("stdio setup ran before authority"),
    )
    monkeypatch.setattr(
        agent_init,
        "_build_client",
        lambda *_args: pytest.fail("client setup ran before authority"),
    )
    try:
        with pytest.raises(RecoveryRefused, match="protected_session_dispatch"):
            agent_init.init_agent(
                SimpleNamespace(), session_id=scope.session_id, session_db=db
            )
    finally:
        db.close()


@pytest.mark.parametrize("explicit", [True, False])
def test_direct_constructor_claim_precedes_first_setup_effect(
    tmp_path, monkeypatch, explicit
):
    db = SessionDB(tmp_path / "state.db")
    agent = SimpleNamespace()
    if not explicit:
        monkeypatch.setattr(
            agent_init, "new_session_id", lambda _now: "generated-session"
        )
    expected = "ordinary-session" if explicit else "generated-session"

    def check_first_effect():
        assert agent.session_id == expected
        with sqlite3.connect(tmp_path / "state.db") as raw:
            assert raw.execute(
                "SELECT session_id FROM recovery_exclusions WHERE kind='ordinary_session'"
            ).fetchone() == (expected,)
        raise RuntimeError("setup sentinel")

    monkeypatch.setattr(agent_init, "_install_safe_stdio", check_first_effect)
    try:
        with pytest.raises(RuntimeError, match="setup sentinel"):
            agent_init.init_agent(
                agent, session_id=expected if explicit else None, session_db=db
            )
    finally:
        db.close()
