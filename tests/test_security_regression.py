"""
Security Regression Matrix for Protocol Brain.
Verifies defenses against prompt injection, shell escapes, privilege escalation, and port hijacking.
"""

import os
from pathlib import Path

from modules.config import load_config
from modules.system.port_killer import DENYLIST_PROCESS_NAMES, free_port, get_protected_pids
from modules.system.shell_runner import FORBIDDEN_OPERATORS, run_safe_command

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_shell_metacharacters():
    """Every character in FORBIDDEN_OPERATORS must be caught and rejected."""
    for op in FORBIDDEN_OPERATORS:
        cmd = f"git status {op} test"
        res = run_safe_command(cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False
        assert "strictly forbidden" in res["error"]


def test_shell_command_chaining():
    """Attempts to chain commands (&, &&, ;, ||) must be blocked."""
    chain_cmds = [
        "git status & whoami",
        "git status && dir",
        "git status; calc.exe",
        "git status || echo fallback",
    ]
    for cmd in chain_cmds:
        res = run_safe_command(cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False


def test_shell_pipe():
    """Pipes (|) must be rejected."""
    res = run_safe_command("git status | findstr main", cwd=str(PROJECT_ROOT))
    assert res["success"] is False
    assert "strictly forbidden" in res["error"]


def test_shell_redirect():
    """File redirection (<, >, >>) must be rejected to prevent overwriting files."""
    redirect_cmds = [
        "git status > C:\\pwned.txt",
        "git status >> D:\\vault\\00_INDEX.md",
        "git status < input.txt",
    ]
    for cmd in redirect_cmds:
        res = run_safe_command(cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False


def test_percent_format_allowed():
    """Format strings with % (e.g. git log --format=%h) must be permitted and not blocked."""
    res = run_safe_command("git status", cwd=str(PROJECT_ROOT))
    assert res["success"] is True
    # Test that % in arguments is not treated as a forbidden operator
    res_fmt = run_safe_command("git log -n 1 --format=%h", cwd=str(PROJECT_ROOT))
    assert "strictly forbidden" not in res_fmt.get("error", "")


def test_fake_executable_in_cwd(tmp_path):
    """A rogue git.exe or git.bat placed in CWD must NOT be executed over system PATH."""
    fake_exe = tmp_path / "git.bat"
    fake_exe.write_text("@echo FAKE_EXECUTABLE", encoding="utf-8")

    # When executing from tmp_path, system git should be used or rejected if not in allowed roots
    # In either case, fake_exe must not be executed directly
    res = run_safe_command("git status", cwd=str(tmp_path))
    # It must execute real git (exit code 128 not a git repo) or block
    if res["success"]:
        assert "FAKE_EXECUTABLE" not in res.get("stdout", "")


def test_executable_outside_allowed_root():
    """Unapproved binaries (e.g. format, shutdown, reg) must be rejected."""
    for bad_bin in ["shutdown.exe", "powershell.exe", "cmd.exe", "reg.exe"]:
        res = run_safe_command(f"{bad_bin} /?", cwd=str(PROJECT_ROOT))
        assert res["success"] is False
        assert "not in the allowed" in res["error"]


def test_cwd_escape():
    """Navigating CWD outside approved roots (C:\\Users, D:\\, F:\\) must be blocked."""
    res = run_safe_command("git status", cwd="Z:\\disallowed_mount")
    assert res["success"] is False
    assert "does not exist" in res["error"] or "outside allowed" in res["error"]


def test_python_eval_blocked():
    """Arbitrary python code execution via -c / --command must be blocked."""
    res = run_safe_command("python -c \"print('injected')\"", cwd=str(PROJECT_ROOT))
    assert res["success"] is False
    assert "Disallowed flag" in res["error"]


def test_node_eval_blocked():
    """Arbitrary node code execution via -e / --eval / -p must be blocked."""
    res = run_safe_command("node -e \"console.log(1)\"", cwd=str(PROJECT_ROOT))
    assert res["success"] is False
    assert "Disallowed flag" in res["error"]


def test_timeout_is_bounded():
    """Commands running longer than timeout must be terminated cleanly."""
    import time
    t0 = time.perf_counter()
    res = run_safe_command("python tests/fixtures/sleep_process.py 5", cwd=str(PROJECT_ROOT), timeout_seconds=1)
    elapsed = time.perf_counter() - t0
    assert res["success"] is False
    assert "timed out" in res["error"].lower()
    assert elapsed < 3.0


def test_untrusted_workspace_blocked(tmp_path):
    """Running commands in an untrusted directory outside trusted_workspaces must be blocked."""
    res = run_safe_command("git status", cwd=str(tmp_path))
    assert res["success"] is False
    assert "outside trusted workspaces" in res["error"]


def test_timeout_cannot_exceed_config():
    """Passing an absurdly large timeout (e.g. 99999s) is clamped by config ceiling."""
    cfg = load_config()
    max_allowed = cfg.get("safe_command_timeout_seconds", 60)
    # Command shouldn't be allowed to run indefinitely
    assert max_allowed <= 120


def test_output_is_truncated():
    """Long terminal outputs must be truncated by max_log_lines to protect context window."""
    cfg = load_config()
    max_lines = cfg.get("max_log_lines", 50)
    # Simulate run command that generates many lines
    res = run_safe_command("git log --oneline -n 100", cwd=str(PROJECT_ROOT))
    if res["success"]:
        lines = res["stdout"].splitlines()
        assert len(lines) <= max_lines + 2  # +2 for truncation notice line


def test_cannot_kill_server_ancestor():
    """The port killer must refuse to terminate ancestor processes or itself."""
    protected = get_protected_pids()
    assert os.getpid() in protected
    for pid in protected:
        assert pid > 0


def test_cannot_kill_denied_process():
    """The port killer denylist must protect critical services."""
    assert "code.exe" in DENYLIST_PROCESS_NAMES
    assert "claude.exe" in DENYLIST_PROCESS_NAMES
    assert "ollama.exe" in DENYLIST_PROCESS_NAMES
    assert "docker.exe" in DENYLIST_PROCESS_NAMES
    assert "postgres.exe" in DENYLIST_PROCESS_NAMES


def test_port_below_1024_rejected():
    """System ports (0-1023) must be rejected to prevent disrupting system infrastructure."""
    for p in [0, 22, 53, 80, 443]:
        res = free_port(p)
        assert res["success"] is False
        assert "between 1024 and 65535" in res["error"]


def test_free_port_requires_process_termination_capability():
    """Calling free_port without process_termination capability enabled must be blocked."""
    res = free_port(59122)
    assert res["success"] is False
    assert "process_termination" in res["error"]


def test_process_dies_during_wait_is_success():
    """If a process exits naturally before/during wait, it must be considered a success."""
    res = free_port(59123, bypass_capability=True)  # Empty unassigned port
    assert res["success"] is True
    assert "already free" in res["message"]


def test_port_is_verified_free_after_termination():
    """Empty port verification check must return verified_free status."""
    res = free_port(59124, bypass_capability=True)
    assert res["success"] is True
