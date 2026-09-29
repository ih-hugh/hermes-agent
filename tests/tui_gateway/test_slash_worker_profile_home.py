"""Tests for TUI gateway slash_worker profile_home propagation (#40677)."""

from unittest.mock import MagicMock, patch


def test_slash_worker_accepts_profile_home(tmp_path):
    """_SlashWorker.__init__ accepts profile_home parameter."""
    # Keep the real constants module available to recovery imports while
    # directing import-time home reads into this test's scratch directory.
    with patch("hermes_constants.get_hermes_home", return_value=tmp_path):
        with patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value.stdout = MagicMock()
            mock_popen.return_value.stderr = MagicMock()

            from tui_gateway.server import _SlashWorker

            # Test initialization with profile_home
            worker = _SlashWorker(
                session_key="test_key",
                model="test-model",
                profile_home="/home/luke/.hermes/profiles/work"
            )

            # Verify Popen was called
            assert mock_popen.called

            # Check that HERMES_HOME was set in the environment
            call_kwargs = mock_popen.call_args[1]
            assert "env" in call_kwargs
            assert call_kwargs["env"]["HERMES_HOME"] == "/home/luke/.hermes/profiles/work"

