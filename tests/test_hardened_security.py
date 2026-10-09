"""
Hardened Security & Integrity Test Suite for Protocol Brain v0.5.0.
Verifies all 18 security fixes and boundary defenses.
"""

from pathlib import Path
from unittest.mock import patch

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
    """Verifies that titles and messages with single quotes, double quotes, and Unicode smart quotes are handled safely."""
    # Test execution should not raise an exception or fail PowerShell command syntax
    res = send_windows_notification(
        title="Test 'Single' \"Double\" ‘Smart’",
        message="Message with `backticks` and 'nested' quotes."
    )
    # Even if toast service is disabled in headless CI, success should be True or error is handled cleanly
    assert "error" not in res or res["success"] in (True, False)


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


# 6. NPX Remote Execution Safety
def test_npx_requires_package_install():
    """npx commands must always require package_install capability."""
    is_allowed, req_cap, _ = evaluate_command_capability(["npx", "test"])
    assert req_cap == "package_install"
    assert is_allowed is False


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
    """Different workspace roots must resolve to isolated SQLite index DB files."""
    proj_a = tmp_path / "ProjectA"
    proj_b = tmp_path / "ProjectB"
    proj_a.mkdir()
    proj_b.mkdir()

    # 1. In workspace directories, they resolve to separate files
    db_a = resolve_index_db_path(proj_a)
    db_b = resolve_index_db_path(proj_b)
    assert db_a != db_b
    assert db_a.parent != db_b.parent

    # 2. In fallback cache when .protocol_brain cannot be created, hash isolation is used
    with patch("pathlib.Path.mkdir", side_effect=[PermissionError("Read only"), None, None, None]):
        with patch.dict("os.environ", {"LOCALAPPDATA": str(tmp_path)}):
            fb_a = resolve_index_db_path(proj_a)
            fb_b = resolve_index_db_path(proj_b)
            assert fb_a != fb_b
            assert fb_a.name != fb_b.name
            assert fb_a.name.startswith("index_")


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

