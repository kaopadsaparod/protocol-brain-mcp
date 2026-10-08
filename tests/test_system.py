"""
Tests for System Operations, Windows Guard, and Shell Allowlist (Happy path + Failure cases).
"""

from pathlib import Path

from modules.system.git_tools import get_git_status
from modules.system.hardware import get_system_health
from modules.system.port_killer import free_port
from modules.system.shell_runner import run_safe_command, sanitize_windows_command

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_system_health_success():
    """Happy path: Gathers CPU, RAM, Disk, and GPU stats without crashing."""
    health = get_system_health()
    assert "cpu_usage_percent" in health
    assert "ram" in health
    assert "disks" in health
    assert "gpu" in health


def test_free_port_on_unused_port():
    """Edge Case: Releasing a port where no process is listening returns cleanly."""
    # Port 59876 is typically unassigned and free
    res = free_port(59876)
    assert res["success"] is True
    assert "already free" in res["message"]
    assert res["terminated"] == []


def test_free_port_invalid_range_failure():
    """Failure Case: Invalid port number returns actionable validation error."""
    res = free_port(-5)
    assert res["success"] is False
    assert "invalid port" in res["error"].lower()

    res_large = free_port(999999)
    assert res_large["success"] is False


def test_shell_runner_allowlist_rejection():
    """Security Failure Case: Commands not in allowlist must be rejected."""
    # Attempt to execute an unallowed utility (e.g. 'curl' or 'calc' or 'format')
    res = run_safe_command("calc.exe", cwd=str(PROJECT_ROOT))
    assert res["success"] is False
    assert "not in the allowed" in res["error"]
    assert res["actionable_hint"] is not None


def test_command_sanitizer_npm_conversion():
    """Happy path: Converts npm to npm.cmd for PowerShell safety."""
    sanitized = sanitize_windows_command("npm install test-package")
    assert "npm.cmd" in sanitized


def test_git_status_on_non_repo_failure(tmp_path):
    """Failure Case: Non-git folder returns actionable error."""
    res = get_git_status(str(tmp_path))
    assert res["success"] is False
    assert "not a git repository" in res["error"]
    assert "git init" in res["actionable_hint"]
