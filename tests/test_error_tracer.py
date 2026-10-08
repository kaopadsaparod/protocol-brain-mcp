"""
Unit tests for Context Engine Error Tracer (trace_error).
Verifies multi-language stack trace parsing, crash site slicing, and actionable recommendations.
"""

from pathlib import Path

import pytest

from modules.context_engine.error_tracer import parse_stack_trace, trace_error


@pytest.fixture
def crash_workspace(tmp_path: Path):
    """Sets up a workspace with a buggy function."""
    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()

    service_file = auth_dir / "service.py"
    service_file.write_text(
        "class AuthService:\n"
        "    def login(self, username: str, user_dict: dict):\n"
        "        # Intentional bug on line 4\n"
        "        token = user_dict['token']\n"
        "        return token\n",
        encoding="utf-8",
    )

    return tmp_path


def test_parse_python_traceback(crash_workspace):
    """Verifies parsing of a standard Python traceback."""
    tb = (
        "Traceback (most recent call last):\n"
        f"  File \"{crash_workspace / 'auth' / 'service.py'}\", line 4, in login\n"
        "    token = user_dict['token']\n"
        "KeyError: 'token'\n"
    )

    parsed = parse_stack_trace(tb, crash_workspace)
    assert parsed["error_type"] == "KeyError"
    assert parsed["error_message"] == "'token'"
    assert len(parsed["frames"]) == 1
    assert parsed["frames"][0].line_number == 4
    assert parsed["frames"][0].symbol_name == "login"
    assert parsed["frames"][0].is_project_file is True


def test_trace_error_end_to_end(crash_workspace):
    """Verifies end-to-end crash site location and actionable diagnosis."""
    tb = (
        "Traceback (most recent call last):\n"
        f"  File \"{crash_workspace / 'auth' / 'service.py'}\", line 4, in login\n"
        "    token = user_dict['token']\n"
        "KeyError: 'token'\n"
    )

    res = trace_error(error_log=tb, workspace_root=str(crash_workspace))
    assert res["success"] is True
    assert res["error_type"] == "KeyError"
    assert res["crash_site"] is not None
    assert res["crash_site"]["line"] == 4
    assert "diagnostic_context" in res
    assert "token = user_dict['token']" in res["diagnostic_context"]
    assert "KeyError" in res["diagnostic_context"]


def test_parse_node_stack_trace(tmp_path: Path):
    """Verifies parsing of Node / TypeScript stack traces."""
    node_err = (
        "TypeError: Cannot read properties of undefined (reading 'getUser')\n"
        f"    at UserService.getUser ({tmp_path / 'auth' / 'service.ts'}:142:15)\n"
        f"    at AuthController.login ({tmp_path / 'auth' / 'controller.ts'}:45:10)\n"
    )

    parsed = parse_stack_trace(node_err, tmp_path)
    assert parsed["error_type"] == "TypeError"
    assert "Cannot read properties" in parsed["error_message"]
    assert len(parsed["frames"]) == 2
    assert parsed["frames"][0].line_number == 142
    assert parsed["frames"][1].line_number == 45


def test_trace_error_empty_log():
    """Empty log must return graceful error with actionable hint."""
    res = trace_error(error_log="")
    assert res["success"] is False
    assert "actionable_hint" in res
