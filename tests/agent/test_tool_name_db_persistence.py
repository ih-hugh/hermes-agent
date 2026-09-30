"""Test that tool_name is correctly persisted to the session DB for tool-result messages.

make_tool_result_message() sets tool_name on every tool-result dict at construction
time. This test verifies that the value survives the flush path into the session DB.
"""
from unittest.mock import MagicMock, patch

from run_agent import AIAgent
from agent.tool_dispatch_helpers import make_tool_result_message


def _make_agent(session_db):
    with (
        patch("model_tools.get_tool_definitions", return_value=[]),
        patch("model_tools.check_toolset_requirements", return_value={}),
        patch("agent.process_bootstrap.OpenAI"),
    ):
        return AIAgent(
            api_key="test-key",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            session_db=session_db,
        )


def test_tool_name_persisted_to_session_db(tmp_path):
    """tool_name set by make_tool_result_message must be passed through to
    the batched flush so the column is populated on first write to the
    session DB."""
    session_db = MagicMock()
    session_db.db_path = tmp_path / "state.db"
    session_db.read_only = False
    session_db._read_all.return_value = []
    session_db._read_one.return_value = None
    agent = _make_agent(session_db)

    messages = [
        {"role": "user", "content": "run a command"},
        make_tool_result_message("terminal", "$ ls\nfile.txt", "c1"),
    ]
    agent._flush_messages_to_session_db(messages)

    assert session_db.append_messages_batch.call_count == 1
    batch = session_db.append_messages_batch.call_args.kwargs["messages"]
    tool_rows = [m for m in batch if m.get("role") == "tool"]
    assert len(tool_rows) == 1
    assert tool_rows[0]["tool_name"] == "terminal"
