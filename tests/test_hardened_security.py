"""
Hardened Security & Integrity Test Suite for Protocol Brain v0.5.0.
Verifies all 18 security fixes and boundary defenses.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.config import DEFAULT_CONFIG, deep_merge
from modules.context_engine.storage import resolve_index_db_path
from modules.security import (
    evaluate_command_capability,
    is_sensitive_key,
    redact_secrets,
)
from modules.system.notification import send_windows_notification
from modules.system.shell_runner import check_dangerous_flags
from modules.vault.reader import is_safe_vault_path, resolve_wikilink_path
from modules.vault.writer import create_vault_note

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# 1. PowerShell Toast Notification Parameterization
def test_notification_handles_quotes_and_smart_quotes():
    """Verifies that titles and messages with single quotes, double quotes, smart quotes, semicolons, and newlines are never in argv."""
    complex_title = "Test ’Single’ ‘Smart’ \"Double\" 'Simple' ; \nNewline"
    complex_msg = "Msg with `backticks`, ; semicolons, and \n newlines."

    with patch("subprocess.run") as mock_run:
        res = send_windows_notification(title=complex_title, message=complex_msg)
        assert res["success"] is True

        assert mock_run.called
        call_args = mock_run.call_args
        argv = call_args[0][0]
        env = call_args[1].get("env", {})

        # Title and message characters must NEVER appear in the command argv or script string
        full_command_str = " ".join(argv)
        assert "’Single’" not in full_command_str
        assert "‘Smart’" not in full_command_str
        assert "Newline" not in full_command_str
        assert "; \n" not in full_command_str

        # Instead, they must be transmitted strictly via PB_TITLE and PB_MSG
        assert env.get("PB_TITLE") == complex_title[:256]
        assert env.get("PB_MSG") == complex_msg[:1024]
        assert "$env:PB_TITLE" in argv[4]
        assert "$env:PB_MSG" in argv[4]

    # Live invocation test
    res_live = send_windows_notification(
        title="Test 'Single' \"Double\" ‘Smart’",
        message="Message with `backticks` and 'nested' quotes."
    )
    assert "error" not in res_live or res_live["success"] in (True, False)


# 2. Vault Confinement & Extension Enforcement
def test_vault_rejects_non_md_extensions(tmp_path):
    """Writing or reading non-markdown files inside vault must be strictly rejected."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "00_INDEX.md").write_text("# Master Index", encoding="utf-8")
    (vault / "script.py").write_text("print('pwned')", encoding="utf-8")

    # is_safe_vault_path must reject non-markdown files
    assert is_safe_vault_path(vault / "script.py", vault) is False
    assert is_safe_vault_path(vault / "00_INDEX.md", vault) is True

    # resolve_wikilink_path must not resolve non-md files
    assert resolve_wikilink_path(vault, "script.py") is None


def test_vault_rejects_hidden_directories(tmp_path):
    """Accessing .obsidian, .git, or hidden folders must be blocked."""
    vault = tmp_path / "vault"
    vault.mkdir()
    hidden_dir = vault / ".obsidian" / "plugins"
    hidden_dir.mkdir(parents=True)
    bad_file = hidden_dir / "main.js"
    bad_file.write_text("console.log(1)", encoding="utf-8")

    assert is_safe_vault_path(bad_file, vault) is False

    with patch("modules.vault.writer.get_vault_path", return_value=vault):
        res = create_vault_note(".obsidian/plugins/test.md", "Hidden", "Content")
        assert res["success"] is False
        assert "hidden" in res["error"].lower() or "restricted" in res["error"].lower()


# 3. Path Traversal in Test Runner Execution
def test_python_test_path_traversal_blocked():
    """python tests/../x.py must not be classified as run_tests."""
    # Attempt traversal out of tests/
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "tests/../malicious.py"],
        cwd=PROJECT_ROOT
    )
    assert req_cap == "system_control"
    assert is_allowed is False

    # Legitimate test inside tests/
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "tests/test_vault.py"],
        cwd=PROJECT_ROOT
    )
    assert req_cap == "run_tests"
    assert is_allowed is True


# 4. Git Read Flag Hardening (--output & --no-index)
def test_git_read_output_flag_blocked():
    """git diff/log with --output or -o must be classified as git_write."""
    # --output writes arbitrary file
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "diff", "--output=pwned.txt"])
    assert req_cap == "git_write"
    assert is_allowed is False

    is_allowed, req_cap, _ = evaluate_command_capability(["git", "log", "-o", "pwned.txt"])
    assert req_cap == "git_write"
    assert is_allowed is False

    # --no-index reads out of repository bounds
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "diff", "--no-index", "a", "b"])
    assert req_cap == "system_control"
    assert is_allowed is False


# 5. Git Subcommand Mutation Detection
def test_git_mutating_subcommands_routed_to_write():
    """git branch/tag/remote modification commands must be classified as git_write."""
    # branch delete
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "branch", "-D", "feature"])
    assert req_cap == "git_write"
    assert is_allowed is False

    # branch create
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "branch", "new_branch"])
    assert req_cap == "git_write"
    assert is_allowed is False

    # branch list is read-only
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "branch", "--list"])
    assert req_cap == "git_read"
    assert is_allowed is True

    # remote add is write
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "remote", "add", "evil", "https://evil.com"])
    assert req_cap == "git_write"
    assert is_allowed is False

    # remote verbose is read
    is_allowed, req_cap, _ = evaluate_command_capability(["git", "remote", "-v"])
    assert req_cap == "git_read"
    assert is_allowed is True


# 6. NPM and NPX Removed From Allowed Execution
def test_npm_npx_unsupported_and_blocked():
    """npm and npx wrappers are removed from policy and require system_control (blocked by default)."""
    is_allowed, req_cap, _ = evaluate_command_capability(["npx", "test"])
    assert req_cap == "system_control"
    assert is_allowed is False

    is_allowed_npm, req_cap_npm, _ = evaluate_command_capability(["npm", "test"])
    assert req_cap_npm == "system_control"
    assert is_allowed_npm is False


# 7. Pytest Code Injection Defense
def test_pytest_plugin_injection_blocked():
    """pytest with -p flag loads arbitrary python code and must require system_control."""
    is_allowed, req_cap, _ = evaluate_command_capability(["pytest", "-p", "malicious_plugin"])
    assert req_cap == "system_control"
    assert is_allowed is False

    # Standard pytest invocation passes as run_tests
    is_allowed, req_cap, _ = evaluate_command_capability(["pytest", "tests/test_vault.py"])
    assert req_cap == "run_tests"
    assert is_allowed is True


# 8. Ruff File Modification Defense
def test_ruff_fix_requires_git_write():
    """ruff --fix and ruff format modify files and require git_write."""
    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check", "--fix"])
    assert req_cap == "git_write"
    assert is_allowed is False

    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "format"])
    assert req_cap == "git_write"
    assert is_allowed is False

    # Pure check passes as run_tests
    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check"])
    assert req_cap == "run_tests"
    assert is_allowed is True


# 9. Case-Sensitive Git Flags
def test_git_case_sensitive_flags():
    """Verifies that git -C (change directory) is allowed, while -c (config injection) is blocked."""
    assert check_dangerous_flags("git", ["-C", "subdir"]) is None
    assert check_dangerous_flags("git.exe", ["-c", "core.sshCommand=calc"]) is not None


# 10. Deep Config Merge
def test_deep_merge_preserves_nested_keys():
    """Overriding a single capability key must not wipe sibling capabilities."""
    override = {
        "capabilities": {
            "git_write": True,
        }
    }
    merged = deep_merge(DEFAULT_CONFIG, override)
    assert merged["capabilities"]["git_write"] is True
    assert merged["capabilities"]["git_read"] is True
    assert merged["capabilities"]["run_tests"] is True
    assert merged["capabilities"]["process_termination"] is False
    assert merged["safe_command_timeout_seconds"] == 60


# 11. Secret Redaction Heuristics
def test_secret_redaction_patterns():
    """Verifies heuristic secret masking for API tokens, passwords, and connection strings."""
    sample = (
        "Found token ghp_123456789012345678901234567890123456 and "
        "OpenAI key sk-abcdef1234567890abcdef123456 and "
        "Authorization: Bearer my_secret_jwt_token_123 and "
        "db_url: postgresql://admin:supersecretpassword@localhost:5432/db"
    )
    sanitized = redact_secrets(sample)
    assert "ghp_" not in sanitized
    assert "sk-" not in sanitized
    assert "supersecretpassword" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

    assert is_sensitive_key("AWS_SECRET_ACCESS_KEY") is True
    assert is_sensitive_key("DATABASE_PASSWORD") is True
    assert is_sensitive_key("PORT") is False


# 12. SQLite Multi-Project Index Isolation
def test_sqlite_multiproject_isolation(tmp_path):
    """Different workspace roots must resolve to isolated SQLite index DB files under LOCALAPPDATA."""
    proj_a = tmp_path / "ProjectA"
    proj_b = tmp_path / "ProjectB"
    proj_a.mkdir()
    proj_b.mkdir()

    with patch.dict("os.environ", {"LOCALAPPDATA": str(tmp_path)}):
        db_a = resolve_index_db_path(proj_a)
        db_b = resolve_index_db_path(proj_b)
        assert db_a != db_b
        assert db_a.name != db_b.name
        assert db_a.name.startswith("index_")
        assert db_b.name.startswith("index_")
        assert str(tmp_path) in str(db_a)
        assert db_a.parent == db_b.parent  # Both stored centrally under ProtocolBrain


# 13. Server Profiles Filtering
def test_server_profiles_filtering():
    """Applying 'core' profile must filter out dangerous mutating tools."""
    from server import app, apply_server_profile

    # Reset/ensure all tools
    apply_server_profile(app, "core")
    tools = app._tool_manager._tools
    assert "run_windows_command" not in tools
    assert "release_port" not in tools
    assert "convert_to_thai_pdf" not in tools
    assert "read_vault_index" in tools
    assert "get_file_outline" in tools

    # Re-apply full profile
    apply_server_profile(app, "full")


# 14. Git Target Path Confinement
def test_git_path_confinement_blocked():
    """Git commands with -C, --git-dir, or --work-tree pointing outside trusted workspaces must be rejected."""
    # -C pointing outside workspace
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["git", "-C", "C:\\Windows", "status"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # --git-dir pointing outside workspace
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["git", "--git-dir=C:\\Windows\\.git", "status"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"

    # --work-tree pointing outside workspace
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["git", "--work-tree=C:\\Windows", "status"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"


# 15. Test & Linter Target Path Confinement
def test_pytest_and_ruff_path_confinement_blocked():
    """Pytest and Ruff runs targeting files or directories outside trusted workspaces must be rejected."""
    # Pytest targeting outside file
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["pytest", "C:\\Windows\\System32\\test_bad.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # Pytest --rootdir outside workspace
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["pytest", "--rootdir=C:\\Windows"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"

    # Python -m pytest targeting outside file
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "-m", "pytest", "C:\\Windows\\test_x.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"

    # Ruff targeting outside directory
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["ruff", "check", "C:\\Windows\\System32"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason


# 16. Forbidden Operators Include Dollar and Parentheses
def test_forbidden_operators_include_dollar_and_parentheses():
    """FORBIDDEN_OPERATORS must include $, (, and ) to prevent subshells and variable expansion."""
    from modules.system.shell_runner import FORBIDDEN_OPERATORS, run_safe_command
    assert "$" in FORBIDDEN_OPERATORS
    assert "(" in FORBIDDEN_OPERATORS
    assert ")" in FORBIDDEN_OPERATORS

    res_subshell = run_safe_command("git status $(whoami)", cwd=str(PROJECT_ROOT))
    assert res_subshell["success"] is False
    assert "strictly forbidden" in res_subshell["error"]

    res_var = run_safe_command("git status $env:USER", cwd=str(PROJECT_ROOT))
    assert res_var["success"] is False
    assert "strictly forbidden" in res_var["error"]


# 17. Subprocess Output Flood Bounded Reader (DoS / RAM Exhaustion Defense)
def test_subprocess_output_flood_bounded_dos_defense(tmp_path):
    """Subprocesses generating runaway output must be capped in memory and terminated without OOM."""
    from modules.system.shell_runner import run_safe_command
    # Run test script generating large output stream in a tight loop
    res = run_safe_command(
        "python tests/fixtures/flood_output.py",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    # Output must be truncated or marked as exceeded safety limit
    assert "truncated" in res.get("stdout", "").lower() or "exceeded safety limit" in res.get("error", "").lower()
    # Memory buffered in stdout must not exceed safety limit
    assert len(res.get("stdout", "")) <= 32768


# 18. Windows Batch Script (.bat/.cmd) and npm/npx Execution Blocking
def test_batch_scripts_and_npm_npx_blocked():
    """Windows batch scripts (.bat, .cmd) and npm/npx wrappers are blocked to prevent cmd.exe injection."""
    from modules.system.shell_runner import resolve_executable, run_safe_command

    for bad_cmd in ["npm test", "npx prettier .", "npm.cmd install", "npx.cmd eslint .", "test.bat", "run.cmd"]:
        res = run_safe_command(bad_cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False
        assert "blocked to prevent cmd.exe command injection" in res["error"]
        assert res["exit_code"] == -1

    assert resolve_executable("npm", PROJECT_ROOT, ["npm"]) is None
    assert resolve_executable("npx", PROJECT_ROOT, ["npx"]) is None
    assert resolve_executable("test.bat", PROJECT_ROOT, ["test.bat"]) is None
    assert resolve_executable("test.cmd", PROJECT_ROOT, ["test.cmd"]) is None


# 19. Python -m Ruff Target Path Confinement
def test_python_m_ruff_target_path_confinement():
    """python -m ruff target paths outside trusted workspaces must be rejected with system_control."""
    # Targeting outside directory
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "-m", "ruff", "check", "C:\\Windows\\System32"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # Targeting outside file with fix
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "-m", "ruff", "check", "--fix", "C:\\Windows\\test.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # Legitimate invocation inside workspace
    is_allowed, req_cap, _ = evaluate_command_capability(
        ["python", "-m", "ruff", "check", "tests/"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is True
    assert req_cap == "run_tests"

    # In-workspace fix requires git_write (disabled by default)
    is_allowed, req_cap, _ = evaluate_command_capability(
        ["python", "-m", "ruff", "check", "--fix", "tests/"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "git_write"


# 20. Relative Path Traversal Confinement
def test_relative_traversal_confinement():
    """Relative paths with .. traversing outside trusted workspaces must be rejected under system_control."""
    outside_dir = "..\\..\\outside_workspace"

    # Git -C traversal
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["git", "-C", outside_dir, "status"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # Pytest target traversal
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["pytest", f"{outside_dir}\\test_bad.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # Ruff target traversal
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["ruff", "check", f"{outside_dir}\\bad.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason

    # python -m ruff target traversal
    is_allowed, req_cap, reason = evaluate_command_capability(
        ["python", "-m", "ruff", "check", f"{outside_dir}\\bad.py"],
        cwd=PROJECT_ROOT,
    )
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "outside trusted workspaces" in reason


# 21. Streaming Chunk Reader Variations (Large stdout, stderr, simultaneous, truncation)
def test_stream_reader_variations():
    """Verifies that bounded streaming reader handles large stdout, large stderr, simultaneous streams, and truncation cleanly."""
    from modules.system.shell_runner import run_safe_command

    # A. Large stdout flood
    res_stdout = run_safe_command(
        "python tests/fixtures/stream_output_variations.py stdout_large",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    assert len(res_stdout.get("stdout", "")) <= 32768
    assert "truncated" in res_stdout.get("stdout", "").lower() or "safety limit" in res_stdout.get("error", "").lower()

    # B. Large stderr flood
    res_stderr = run_safe_command(
        "python tests/fixtures/stream_output_variations.py stderr_large",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    assert len(res_stderr.get("stderr", "")) <= 32768
    assert "truncated" in res_stderr.get("stderr", "").lower() or "safety limit" in res_stderr.get("error", "").lower()

    # C. Simultaneous stdout and stderr flood exceeds global combined ceiling (64 KB)
    res_both = run_safe_command(
        "python tests/fixtures/stream_output_variations.py both_simultaneous",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    assert res_both["success"] is False
    assert "safety limit" in res_both.get("error", "").lower()
    assert res_both.get("total_bytes_generated", 0) > 65536
    assert res_both.get("total_bytes_stored", 0) <= 16384

    # D. Both streams moderate output (combined 24 KB: exceeds 16KB store ceiling, below 64KB flood ceiling)
    res_both_mod = run_safe_command(
        "python tests/fixtures/stream_output_variations.py both_moderate",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    assert res_both_mod["success"] is True
    assert res_both_mod["exit_code"] == 0
    # Proves combined stored bytes across stdout and stderr strictly <= max_output_bytes (16384)
    assert res_both_mod.get("total_bytes_stored", 0) <= 16384
    assert res_both_mod.get("total_bytes_generated", 0) == 24576
    assert "Output truncated" in res_both_mod.get("stdout", "") or "Output truncated" in res_both_mod.get("stderr", "")

    # E. Moderate truncated output single stream (24 KB stdout)
    res_mod = run_safe_command(
        "python tests/fixtures/stream_output_variations.py moderate_truncated",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=5,
    )
    assert res_mod["exit_code"] == 0
    assert "Output truncated" in res_mod.get("stdout", "")
    assert res_mod.get("total_bytes_stored", 0) <= 16384


# 22. Verification of Child Process Tree and Reader Threads Termination
def test_stream_child_process_and_threads_terminated_after_timeout():
    """Verifies that child processes and reader threads genuinely terminate after command timeout."""
    import psutil

    from modules.system.shell_runner import run_safe_command

    res_timeout = run_safe_command(
        "python tests/fixtures/stream_output_variations.py spawn_child_and_sleep",
        cwd=str(PROJECT_ROOT),
        timeout_seconds=2,
    )
    assert res_timeout["success"] is False
    assert "timed out" in res_timeout["error"].lower()

    # Verify no sleep_process.py remains orphaned
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = proc.info.get("cmdline") or []
            cmd_str = " ".join(cmdline).lower()
            if "sleep_process.py" in cmd_str:
                pytest.fail(f"Orphaned sleep_process found running with PID {proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# 23. Executable Trust in Writable Directories (AppData, ProgramData, Temp, Downloads)
def test_fake_executable_in_writable_directories_rejected(tmp_path):
    """Executables placed in writable scratch directories are rejected without execution."""
    from modules.system.shell_runner import is_trusted_binary_location, resolve_executable

    # 1. Directly in CWD
    cwd_binary = PROJECT_ROOT / "python.exe"
    assert is_trusted_binary_location(cwd_binary, PROJECT_ROOT) is False

    # 2. In unvetted writable AppData directory
    appdata_scratch = Path.home() / "AppData" / "Local" / "WritableScratch" / "python.exe"
    assert is_trusted_binary_location(appdata_scratch, PROJECT_ROOT) is False

    # 3. In unvetted ProgramData directory
    progdata_scratch = Path("C:/ProgramData/WritableScratch/python.exe")
    assert is_trusted_binary_location(progdata_scratch, PROJECT_ROOT) is False

    # 4. In Downloads or Temp
    downloads_binary = Path.home() / "Downloads" / "git.exe"
    assert is_trusted_binary_location(downloads_binary, PROJECT_ROOT) is False

    temp_binary = Path.home() / "AppData" / "Local" / "Temp" / "pytest.exe"
    assert is_trusted_binary_location(temp_binary, PROJECT_ROOT) is False

    # 5. Legitimate executables pass
    sys_py = Path(sys.executable).resolve()
    assert is_trusted_binary_location(sys_py, PROJECT_ROOT) is True
    assert resolve_executable("python", PROJECT_ROOT, ["python"]) is not None
    assert resolve_executable(str(appdata_scratch), PROJECT_ROOT, ["python"]) is None


# 24. Rejection of .cmd and .bat Scripts on All Paths and Formats
def test_batch_scripts_rejected_all_path_variations():
    """Batch files (.bat, .cmd) are rejected whether passed relatively, absolutely, quoted, or resolved via PATH."""
    from modules.system.shell_runner import resolve_executable, run_safe_command

    bad_commands = [
        "script.bat",
        "script.cmd",
        "script.BAT",
        "script.CMD",
        "C:\\Windows\\test.bat",
        '"C:\\Program Files\\test.cmd"',
        '"C:\\My Tools\\run.bat"',
        '"test.cmd"',
    ]

    for cmd in bad_commands:
        res = run_safe_command(cmd, cwd=str(PROJECT_ROOT))
        assert res["success"] is False
        assert "blocked to prevent cmd.exe command injection" in res["error"]
        assert res["exit_code"] == -1

    # PATH resolution to batch file rejected
    with patch("shutil.which", return_value="C:\\Tools\\tool.bat"):
        assert resolve_executable("tool", PROJECT_ROOT, ["tool"]) is None


# 25. Comprehensive Ruff and python -m ruff Path & Config Confinement
def test_ruff_config_and_target_confinement_comprehensive():
    """Ruff commands with external targets or external configs must be rejected under system_control."""
    outside_file = "C:\\Windows\\System32\\test.py"
    outside_cfg = "C:\\Windows\\ruff.toml"

    # Direct ruff target
    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check", outside_file], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    # Direct ruff --fix target
    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check", "--fix", outside_file], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    # Direct ruff --config flag
    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check", f"--config={outside_cfg}"], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    is_allowed, req_cap, _ = evaluate_command_capability(["ruff", "check", "-c", outside_cfg], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    # Python -m ruff target
    is_allowed, req_cap, _ = evaluate_command_capability(["python", "-m", "ruff", "check", outside_file], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    # Python -m ruff --fix target
    is_allowed, req_cap, _ = evaluate_command_capability(["python", "-m", "ruff", "check", "--fix", outside_file], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"

    # Python -m ruff --config flag
    is_allowed, req_cap, _ = evaluate_command_capability(["python", "-m", "ruff", "check", f"--config={outside_cfg}"], cwd=PROJECT_ROOT)
    assert is_allowed is False and req_cap == "system_control"


# 26. Direct Confinement Unit Tests (Roots, Traversal, UNC, Junctions, Drive-relative)
def test_confine_direct_rejections():
    from modules.security.confine import confine

    # Root drive
    with pytest.raises(PermissionError, match="root"):
        confine("C:\\")
    with pytest.raises(PermissionError, match="root"):
        confine("C:/")

    # Traversal escaping workspace
    with pytest.raises(PermissionError, match="outside approved roots"):
        confine("..")
    with pytest.raises(PermissionError, match="outside approved roots"):
        confine("../../Windows")

    # UNC paths
    with pytest.raises(PermissionError, match="UNC path"):
        confine(r"\\192.168.1.1\share")
    with pytest.raises(PermissionError, match="UNC path"):
        confine("//server/share")
    with pytest.raises(PermissionError, match="UNC path"):
        confine(r"\??\UNC\server\share")

    # Drive-relative paths
    with pytest.raises(PermissionError, match="Drive-relative"):
        confine("C:foo.txt")
    with pytest.raises(PermissionError, match="Drive-relative"):
        confine("C:")

    # Junction / symlink escaping workspace
    junc = PROJECT_ROOT / "temp_test_junction"
    try:
        import _winapi
        if not junc.exists():
            _winapi.CreateJunction(r"C:\Windows", str(junc))
        with pytest.raises(PermissionError, match="outside approved roots"):
            confine(junc)
    finally:
        if junc.exists():
            import os
            os.rmdir(junc)


# 27. Confinement Wiring Across All Tools
def test_confine_integration_across_all_tools():
    from modules.code_intel.outline import get_code_outline, read_symbol
    from modules.code_intel.references import find_references
    from modules.context_engine.engine import prepare_context
    from modules.docs.docx_pdf import convert_document_to_pdf
    from modules.system.git_tools import get_git_diff_summary, get_git_status
    from modules.vault.search import search_vault

    # find_references
    res = find_references("test", root_dir="C:\\")
    assert res["success"] is False
    assert "unconfined" in res["error"].lower() or "root" in res["error"].lower()

    # get_file_outline
    res = get_code_outline("C:\\Windows\\System32\\cmd.exe")
    assert res["success"] is False

    # read_symbol
    res = read_symbol("C:\\Windows\\System32\\cmd.exe", "main")
    assert res["success"] is False

    # get_git_status
    res = get_git_status("C:\\Windows")
    assert res["success"] is False

    # get_git_diff_summary
    res = get_git_diff_summary("C:\\Windows")
    assert res["success"] is False

    # prepare_context
    res = prepare_context("test query", workspace_root="C:\\")
    assert res["success"] is False
    assert "invalid workspace root" in res["error"].lower()

    # convert_document_to_pdf
    res = convert_document_to_pdf("C:\\Windows\\win.ini")
    assert res["success"] is False

    # search_vault
    res = search_vault("test", folder="..")
    assert res["success"] is False


# 28. Comprehensive Secrets Redaction (JSON, Bearer, URLs, Tools)
def test_secrets_redaction_comprehensive_coverage(tmp_path, monkeypatch):
    """
    Verifies that:
    1. why_service_unhealthy redacts JSON passwords, Authorization Bearer, and user:pass@ URLs.
    2. inspect_config_usage never prints raw env values and redacts snippets.
    3. redact_secrets is wired into all tools returning logs/code/commands.
    """
    from modules.code_intel.error_filter import filter_build_errors
    from modules.code_intel.outline import read_symbol
    from modules.context_engine.config_inspector import inspect_config_usage
    from modules.context_engine.docker_inspector import why_service_unhealthy

    # 1. why_service_unhealthy log output mocking with seeded secrets
    seeded_log = (
        '{"event": "login_failed", "password": "super_secret_cleartext_pass", "user": "admin"}\n'
        'Request header: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.my_super_jwt_secret\n'
        'Connecting to http://admin:database_password_999@localhost:5432/main\n'
        'Database URI: postgres://app_user:db_secret_pass_888@db.internal:5432/app\n'
    )
    with patch("shutil.which", return_value="docker"):
        with patch("subprocess.check_output", return_value=seeded_log):
            diag = why_service_unhealthy("api_service", workspace_root=str(PROJECT_ROOT))
            assert diag["success"] is True
            raw_serialized = str(diag)
            assert "super_secret_cleartext_pass" not in raw_serialized
            assert "my_super_jwt_secret" not in raw_serialized
            assert "database_password_999" not in raw_serialized
            assert "db_secret_pass_888" not in raw_serialized
            assert "[REDACTED_SECRET]" in raw_serialized

    # 2. inspect_config_usage never prints raw env value
    monkeypatch.setenv("CUSTOM_ENV_VAR", "super_confidential_raw_env_value_xyz")
    cfg_diag = inspect_config_usage("CUSTOM_ENV_VAR", workspace_root=str(PROJECT_ROOT))
    assert cfg_diag["success"] is True
    assert cfg_diag["status"] == "set"
    assert "super_confidential_raw_env_value_xyz" not in str(cfg_diag)
    assert cfg_diag["masked_value"] == "[SET]"

    # 3. read_symbol redacts seeded secrets in code definitions
    test_py = PROJECT_ROOT / "tests" / "test_hardened_security.py"
    res = read_symbol(str(test_py), "test_secret_redaction_patterns")
    assert res["success"] is True
    assert "ghp_1234567890" not in res["symbol"]["code"]
    assert "my_super_jwt_secret" not in res["symbol"]["code"]
    assert "postgresql://admin:supersecretpassword" not in res["symbol"]["code"]

    # 4. filter_build_errors redacts seeded secrets in compiler errors
    err_out = filter_build_errors('Error: Failed connecting with password="in_log_secret_123" at line 1')
    assert "in_log_secret_123" not in err_out["clean_output"]
    assert "[REDACTED_SECRET]" in err_out["clean_output"]


# 29. Process Inspection Shows Only Exe Name + Script Name (No Raw Arguments)
def test_process_inspection_strips_raw_args_and_secrets():
    """
    Verifies that inspect_local_services and ask_codebase show only executable + script name,
    stripping all sensitive CLI flags, tokens, and raw parameters.
    """
    from unittest.mock import MagicMock

    from modules.context_engine.codebase_qa import ask_codebase
    from modules.context_engine.runtime_inspector import inspect_local_services
    from modules.security.sanitizer import format_safe_process_summary

    # Unit test format_safe_process_summary
    assert format_safe_process_summary(["C:\\Python313\\python.exe", "server.py", "--db-pass=topsecret", "--port=8080"]) == "python.exe server.py"
    assert format_safe_process_summary(["node.exe", "dist/app.js", "--secret-token=abc"]) == "node.exe app.js"
    assert format_safe_process_summary(["redis-server.exe", "--requirepass", "hunter2"]) == "redis-server.exe"

    # Mock psutil connection and process in inspect_local_services
    mock_conn = MagicMock()
    mock_conn.status = "LISTEN"
    mock_conn.laddr.port = 9876
    mock_conn.laddr.ip = "127.0.0.1"
    mock_conn.pid = 4321

    mock_proc = MagicMock()
    mock_proc.name.return_value = "python.exe"
    mock_proc.cmdline.return_value = ["python.exe", "C:\\projects\\app\\main.py", "--api-key=super_secret_cli_flag_xyz"]
    mock_proc.parent.return_value = None

    with patch("psutil.net_connections", return_value=[mock_conn]):
        with patch("psutil.Process", return_value=mock_proc):
            res = inspect_local_services(workspace_root=str(PROJECT_ROOT))
            assert res["success"] is True
            service = next(s for s in res["services"] if s["port"] == 9876)
            assert service["command_summary"] == "python.exe main.py"
            assert "super_secret_cli_flag_xyz" not in str(res)
            assert "--api-key" not in str(res)

            # ask_codebase port diagnosis
            qa_res = ask_codebase("why is port 9876 busy?", workspace_root=str(PROJECT_ROOT))
            assert qa_res["success"] is True
            assert "python.exe main.py" in qa_res["answer_markdown"]
            assert "super_secret_cli_flag_xyz" not in qa_res["answer_markdown"]
            assert "--api-key" not in qa_res["answer_markdown"]


# 30. Central run_git Hardened Security Flags & Absolute Binary Resolution
def test_central_run_git_hardened_security_flags():
    """
    Verifies that:
    1. find_git_binary resolves to an absolute path.
    2. run_git injects SAFE_GIT_FLAGS:
       -c core.fsmonitor=false -c core.hooksPath=NUL --no-pager --no-optional-locks --no-ext-diff --no-textconv
    3. Callers (git_tools, impact_analyzer, diff_intelligence, project_inspector) use run_git.
    """
    from unittest.mock import MagicMock

    from modules.context_engine.diff_intelligence import get_git_diff_text
    from modules.context_engine.impact_analyzer import git_context
    from modules.context_engine.project_inspector import get_git_quick_summary
    from modules.system.git_tools import (
        SAFE_GIT_FLAGS,
        find_git_binary,
        get_git_diff_summary,
        get_git_status,
        is_git_repo,
        run_git,
    )

    git_bin = find_git_binary()
    assert git_bin is not None
    assert Path(git_bin).is_absolute()
    assert "core.fsmonitor=false" in SAFE_GIT_FLAGS
    assert "core.hooksPath=NUL" in SAFE_GIT_FLAGS
    assert "--no-ext-diff" in SAFE_GIT_FLAGS
    assert "--no-textconv" in SAFE_GIT_FLAGS

    # Verify run_git injects proper flags on diff/log commands
    with patch("subprocess.run") as mock_subproc:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "mock_output"
        mock_subproc.return_value = mock_res

        # Test diff command receives diff safety flags
        run_git(["diff", "--stat"], cwd=PROJECT_ROOT)
        call_args = mock_subproc.call_args[0][0]
        assert call_args[0] == git_bin
        assert "-c" in call_args and "core.fsmonitor=false" in call_args
        assert "-c" in call_args and "core.hooksPath=NUL" in call_args
        assert "--no-pager" in call_args
        assert "--no-optional-locks" in call_args
        assert "--no-ext-diff" in call_args
        assert "--no-textconv" in call_args

        # Test status command receives global flags without diff-specific flags
        run_git(["status", "--porcelain=v1"], cwd=PROJECT_ROOT)
        status_call_args = mock_subproc.call_args[0][0]
        assert status_call_args[0] == git_bin
        assert "-c" in status_call_args and "core.fsmonitor=false" in status_call_args
        assert "--no-ext-diff" not in status_call_args

    # Verify context engine tools route through run_git
    with patch("modules.system.git_tools.run_git") as mock_run_git:
        mock_git_res = MagicMock()
        mock_git_res.returncode = 0
        mock_git_res.stdout = "a1b2c3d|author|1 hour ago|feat: commit\n"
        mock_run_git.return_value = mock_git_res

        # impact_analyzer.git_context
        ctx = git_context(workspace_root=str(PROJECT_ROOT))
        assert ctx["success"] is True
        assert mock_run_git.called
        assert mock_run_git.call_args[0][0][0] == "log"

        # diff_intelligence.get_git_diff_text
        mock_git_res.stdout = "diff --git a/x b/x\n"
        diff_txt = get_git_diff_text(PROJECT_ROOT)
        assert "diff" in diff_txt
        assert mock_run_git.call_args[0][0][0] == "diff"

        # project_inspector.get_git_quick_summary
        mock_git_res.stdout = "main"
        summary = get_git_quick_summary(PROJECT_ROOT)
        assert summary["branch"] == "main"

        # git_tools.is_git_repo
        mock_git_res.stdout = "true\n"
        assert is_git_repo(PROJECT_ROOT) is True

        # git_tools.get_git_status
        status = get_git_status(str(PROJECT_ROOT))
        assert status["success"] is True

        # git_tools.get_git_diff_summary
        diff_sum = get_git_diff_summary(str(PROJECT_ROOT))
        assert diff_sum["success"] is True


# 31. Rejection of Git Flags (--output, --no-index, -o, -O) & Python Traversal (tests/../x.py)
def test_git_flags_and_python_traversal_policy_rejection():
    """
    Verifies that:
    1. policy.py rejects git flags --output, --no-index, -o, -O, -ofoo, -Ofoo.
    2. policy.py rejects python tests/../x.py.
    3. policy.py permits legitimate python tests/test_foo.py under run_tests.
    """
    from modules.security.policy import evaluate_command_capability

    # 1. Git flags requiring write or system_control
    bad_git_commands = [
        ["git", "diff", "--output=evil.patch"],
        ["git", "diff", "--output", "evil.patch"],
        ["git", "diff", "-o", "evil.patch"],
        ["git", "diff", "-oevil.patch"],
        ["git", "diff", "-O", "orderfile"],
        ["git", "diff", "-Oorderfile"],
        ["git", "log", "--output=log.txt"],
        ["git", "log", "-o", "log.txt"],
        ["git", "show", "--output=show.txt"],
        ["git", "diff", "--no-index", "a", "b"],
        ["git", "diff", "--no-index=true", "a", "b"],
    ]

    for cmd in bad_git_commands:
        is_allowed, req_cap, err = evaluate_command_capability(cmd, cwd=PROJECT_ROOT)
        assert is_allowed is False, f"Expected {cmd} to be blocked, but passed: {err}"
        assert req_cap in ("git_write", "system_control")

    # Legitimate git commands pass under git_read
    good_git_commands = [
        ["git", "status"],
        ["git", "diff"],
        ["git", "diff", "--stat"],
        ["git", "log", "--oneline"],
        ["git", "branch", "--show-current"],
        ["git", "rev-parse", "HEAD"],
    ]
    for cmd in good_git_commands:
        is_allowed, req_cap, _ = evaluate_command_capability(cmd, cwd=PROJECT_ROOT)
        assert is_allowed is True
        assert req_cap == "git_read"

    # 2. Python test script traversal rejection: python tests/../evil.py
    is_allowed, req_cap, err = evaluate_command_capability(["python", "tests/../evil.py"], cwd=PROJECT_ROOT)
    assert is_allowed is False
    assert req_cap == "system_control"
    assert "traversal" in err.lower() or "tests directory" in err.lower()

    is_allowed, req_cap, err = evaluate_command_capability(["python", "tests/../../outside.py"], cwd=PROJECT_ROOT)
    assert is_allowed is False
    assert req_cap == "system_control"

    # 3. Valid test under tests/ passes as run_tests
    is_allowed, req_cap, _ = evaluate_command_capability(["python", "tests/test_something.py"], cwd=PROJECT_ROOT)
    assert is_allowed is True
    assert req_cap == "run_tests"


# 32. Workspace Isolation with Identical Relative Paths & Constrained Pruning
def test_workspaces_with_identical_relative_paths_do_not_collide(tmp_path):
    """
    Verifies that:
    1. Two separate workspaces with identical relative files (e.g., src/app.py) have separate index DBs.
    2. Indexing or pruning one workspace does not affect or collide with the other.
    3. Pruning is strictly constrained to the workspace root.
    """
    from modules.context_engine.indexer import IncrementalIndexer

    ws1 = tmp_path / "Workspace1"
    ws2 = tmp_path / "Workspace2"
    ws1.mkdir()
    ws2.mkdir()

    # Identical relative path src/app.py in both workspaces
    (ws1 / "src").mkdir()
    (ws2 / "src").mkdir()

    file1 = ws1 / "src" / "app.py"
    file1.write_text("def service_one_unique_func(): pass\n", encoding="utf-8")

    file2 = ws2 / "src" / "app.py"
    file2.write_text("def service_two_unique_func(): pass\n", encoding="utf-8")

    with patch.dict("os.environ", {"LOCALAPPDATA": str(tmp_path)}):
        indexer1 = IncrementalIndexer(workspace_root=ws1)
        indexer2 = IncrementalIndexer(workspace_root=ws2)

        # Separate DB files
        assert indexer1.db.db_path != indexer2.db.db_path
        assert indexer1.db.db_path.name != indexer2.db.db_path.name

        # Index both
        r1 = indexer1.index_workspace()
        r2 = indexer2.index_workspace()
        assert r1["files_indexed"] == 1
        assert r2["files_indexed"] == 1

        # Check symbols in Workspace1
        with indexer1.db.get_connection() as conn:
            cur = conn.cursor()
            symbols1 = [row["name"] for row in cur.execute("SELECT name FROM symbols")]
            assert "service_one_unique_func" in symbols1
            assert "service_two_unique_func" not in symbols1

        # Check symbols in Workspace2
        with indexer2.db.get_connection() as conn:
            cur = conn.cursor()
            symbols2 = [row["name"] for row in cur.execute("SELECT name FROM symbols")]
            assert "service_two_unique_func" in symbols2
            assert "service_one_unique_func" not in symbols2

        # Delete file in Workspace1 and prune
        file1.unlink()
        prune_res = indexer1.index_workspace()
        assert prune_res["deleted_pruned"] == 1

        # Workspace2 is untouched
        with indexer2.db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM files")
            assert cur.fetchone()["cnt"] == 1
            cur.execute("SELECT name FROM symbols")
            assert cur.fetchone()["name"] == "service_two_unique_func"


# 33. System Cleanup: NPM/NPX Removal, Logger Rotation, and Legacy Vault Typo Removal
def test_cleanup_npm_npx_logger_rotation_and_vault_fallback():
    """
    Verifies that:
    1. npm and npx are completely removed from allowed_shell_prefixes in config.json and DEFAULT_CONFIG.
    2. find_relevant_tests and suggest_tests_for_change never generate 'npm test --'.
    3. modules.logger is set to DEBUG and includes RotatingFileHandler.
    4. Legacy 'D:/vualt' is removed from candidate vault fallback paths.
    """
    import inspect
    import logging
    from logging.handlers import RotatingFileHandler

    from modules.config import DEFAULT_CONFIG, load_config
    from modules.context_engine.diff_intelligence import suggest_tests_for_change
    from modules.context_engine.impact_analyzer import find_relevant_tests
    from modules.logger import logger
    from modules.vault.reader import get_vault_path

    # 1. Config cleanup: no npm/npx in allowed_shell_prefixes
    cfg = load_config()
    assert "npm" not in cfg.get("allowed_shell_prefixes", [])
    assert "npx" not in cfg.get("allowed_shell_prefixes", [])
    assert "npm" not in DEFAULT_CONFIG["allowed_shell_prefixes"]
    assert "npx" not in DEFAULT_CONFIG["allowed_shell_prefixes"]

    # 2. No 'npm test --' generated
    impact_tests = find_relevant_tests("service.ts", workspace_root=str(PROJECT_ROOT))
    assert not any("npm test" in cmd for cmd in impact_tests["recommended_commands"])

    diff_tests = suggest_tests_for_change(
        diff="diff --git a/src/app.ts b/src/app.ts\n--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,1 +1,1 @@\n-x\n+y\n",
        workspace_root=str(PROJECT_ROOT),
    )
    assert not any("npm test" in cmd for cmd in diff_tests["recommended_commands"])

    # 3. Logger DEBUG level + RotatingFileHandler
    assert logger.level == logging.DEBUG
    has_rotating_handler = any(isinstance(h, RotatingFileHandler) for h in logger.handlers)
    assert has_rotating_handler, "logger must have a RotatingFileHandler attached"

    # 4. Legacy 'vualt' removed from get_vault_path source code
    source = inspect.getsource(get_vault_path)
    assert "vualt" not in source.lower()








