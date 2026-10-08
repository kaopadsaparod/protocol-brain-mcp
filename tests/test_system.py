"""
Tests for System Operations, Windows Guard, Port Killer, and Shell Security.
"""

import json
from pathlib import Path

from modules.config import load_config
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
    res = free_port(59876)
    assert res["success"] is True
    assert "already free" in res["message"]
    assert res["terminated"] == []


def test_free_port_privileged_range_rejection():
    """Security Failure Case: Privileged/system ports (< 1024) must be blocked."""
    res_80 = free_port(80)
    assert res_80["success"] is False
    assert "between 1024 and 65535" in res_80["error"]

    res_neg = free_port(-5)
    assert res_neg["success"] is False

    res_large = free_port(999999)
    assert res_large["success"] is False


def test_shell_runner_operator_injection_rejection():
    """Security Failure Case: Metacharacters and command chaining must be rejected."""
    bad_commands = [
        "git status & del /s /q D:\\vault",
        "git status && dir",
        "git status | echo pwned",
        "git status > out.txt",
        "git status ^%VAR^%",
        "git status\ndel D:\\vault",
        "git status; ls",
    ]
    for cmd in bad_commands:
        res = run_safe_command(cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False
        assert "strictly forbidden" in res["error"]
        assert res["actionable_hint"] is not None


def test_shell_runner_dangerous_flag_rejection():
    """Security Failure Case: Inline code execution flags (-c, -e) must be rejected."""
    res_py = run_safe_command("python -c \"print(123)\"", cwd=str(PROJECT_ROOT))
    assert res_py["success"] is False
    assert "Disallowed flag" in res_py["error"]

    res_node = run_safe_command("node -e \"console.log(123)\"", cwd=str(PROJECT_ROOT))
    assert res_node["success"] is False
    assert "Disallowed flag" in res_node["error"]


def test_shell_runner_allowlist_rejection():
    """Security Failure Case: Commands not in allowlist must be rejected."""
    res = run_safe_command("calc.exe", cwd=str(PROJECT_ROOT))
    assert res["success"] is False
    assert "not in the allowed" in res["error"]


def test_shell_runner_cwd_out_of_bounds_rejection():
    """Security Failure Case: CWD outside allowed roots must be rejected."""
    # Attempt to point to non-existent or disallowed root
    res = run_safe_command("git status", cwd="Z:\\disallowed_drive")
    assert res["success"] is False
    assert "does not exist" in res["error"] or "outside allowed" in res["error"]


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


def test_config_local_override(tmp_path):
    """Happy path: config.local.json overrides default configuration."""
    test_local = PROJECT_ROOT / "config.local.json"
    try:
        with open(test_local, "w", encoding="utf-8") as f:
            json.dump({"custom_test_key": "override_value"}, f)

        cfg = load_config()
        assert cfg.get("custom_test_key") == "override_value"
    finally:
        if test_local.exists():
            test_local.unlink()
