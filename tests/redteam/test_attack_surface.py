"""
Tier 2 Red-Team Attack Surface Tests for Protocol Brain on Windows.
Verifies defense-in-depth against:
- Toast PowerShell script injection
- Vault hidden/non-markdown modification bypasses
- Path confinement evasion (UNC, 8.3 names, NTFS ADS, DOS device names, escaping junctions)
- Poisoned git repository configurations (fsmonitor, diff.external, hooks)
- Cross-workspace SQLite database isolation
"""

import hashlib
import subprocess

import psutil
import pytest

from modules.context_engine.indexer import IncrementalIndexer
from modules.context_engine.storage import IndexStorage, resolve_index_db_path
from modules.security.confine import (
    add_trusted_workspace,
    confine,
    remove_trusted_workspace,
)
from modules.system.git_tools import get_git_diff_summary, get_git_status
from modules.system.notification import send_windows_notification
from modules.vault.writer import (
    append_to_existing_note,
    create_vault_note,
    update_note_frontmatter,
)

# =====================================================================
# 1. Toast Notification Injection Attack Vectors
# =====================================================================

def test_toast_notification_powershell_injection_prevented(monkeypatch):
    """
    Ensures arbitrary PowerShell payload injected into title or message
    never executes secondary commands or enters command arguments.
    """
    executed_commands = []

    def mock_run(cmd, *args, **kwargs):
        executed_commands.append({"cmd": cmd, "env": kwargs.get("env", {})})
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("modules.system.notification.subprocess.run", mock_run)

    malicious_payloads = [
        "a’); Start-Process notepad; (‘",
        'a"); Start-Process notepad; ("',
        "test`; Start-Process calc.exe `;",
        "test\nStart-Process notepad\n",
        '$(Start-Process notepad)',
        '"; [System.Diagnostics.Process]::Start("notepad.exe"); #',
    ]

    for payload in malicious_payloads:
        executed_commands.clear()
        res = send_windows_notification(payload, "Benign message content")
        assert res["success"] is True
        assert len(executed_commands) == 1
        cmd_str = " ".join(executed_commands[0]["cmd"])
        # Invariant: PowerShell command string must be static and NEVER contain payload
        assert "notepad" not in cmd_str
        assert "calc.exe" not in cmd_str
        assert payload not in cmd_str


def test_toast_notification_never_interpolates_title_or_message_in_argv(monkeypatch):
    """
    User Requirement: Title and message with special characters (’ ‘ " ' ; newline)
    must NEVER appear in argv or script strings passed to powershell.
    They must be passed exclusively through environment variables (PB_TITLE, PB_MSG).
    """
    recorded_commands = []

    def mock_run(cmd, *args, **kwargs):
        recorded_commands.append({"cmd": cmd, "env": kwargs.get("env", {})})
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("modules.system.notification.subprocess.run", mock_run)

    special_payloads = [
        "Special’Title‘With\"Quotes'And;Semicolons\nNewline",
        "Payload`With$Special()Characters",
    ]

    for p in special_payloads:
        recorded_commands.clear()
        send_windows_notification(p, f"Message::{p}")
        assert len(recorded_commands) == 1
        cmd_str = " ".join(recorded_commands[0]["cmd"])
        assert p not in cmd_str, f"Payload interpolated directly into PowerShell command string: {cmd_str}"
        assert f"Message::{p}" not in cmd_str, "Message interpolated directly into PowerShell command string!"
        # Verify passed exclusively through environment
        env = recorded_commands[0]["env"]
        assert env.get("PB_TITLE") == p[:256]


# =====================================================================
# 2. Vault Non-Markdown and Hidden Directory Access
# =====================================================================

def test_vault_rejects_hidden_and_non_markdown_targets(tmp_path, monkeypatch):
    """
    Attempts to mutate or access protected files (.obsidian/, conftest.py, .env)
    must fail cleanly without altering existing files or their hashes.
    """
    vault_dir = tmp_path / "mock_vault"
    vault_dir.mkdir()
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault_dir))

    # Setup pre-existing protected files
    obsidian_plugin_dir = vault_dir / ".obsidian" / "plugins" / "sample"
    obsidian_plugin_dir.mkdir(parents=True)
    plugin_js = obsidian_plugin_dir / "main.js"
    plugin_js.write_text("console.log('original');", encoding="utf-8")
    original_plugin_hash = hashlib.sha256(plugin_js.read_bytes()).hexdigest()

    conftest_py = vault_dir / "conftest.py"
    conftest_py.write_text("# pytest configuration\n", encoding="utf-8")
    original_conftest_hash = hashlib.sha256(conftest_py.read_bytes()).hexdigest()

    # Setup valid markdown note
    valid_note = vault_dir / "Daily.md"
    valid_note.write_text("# Daily\nInitial note.\n", encoding="utf-8")

    # 1. Attempt append to .obsidian plugin file
    res = append_to_existing_note(".obsidian/plugins/sample/main.js", "evil_code()")
    assert res["success"] is False
    assert hashlib.sha256(plugin_js.read_bytes()).hexdigest() == original_plugin_hash

    # 2. Attempt append to conftest.py
    res = append_to_existing_note("conftest.py", "import os; os.system('calc')")
    assert res["success"] is False
    assert hashlib.sha256(conftest_py.read_bytes()).hexdigest() == original_conftest_hash

    # 3. Attempt update frontmatter on conftest.py
    res = update_note_frontmatter("conftest.py", {"malicious": "value"})
    assert res["success"] is False
    assert hashlib.sha256(conftest_py.read_bytes()).hexdigest() == original_conftest_hash

    # 4. Attempt creating note in hidden folder
    res = create_vault_note(".obsidian/hacked.md", "Hacked", "Should fail")
    assert res["success"] is False

    # 5. Attempt path traversal escape from vault
    res = create_vault_note("../escaped_note.md", "Escape", "Should fail")
    assert res["success"] is False
    assert not (tmp_path / "escaped_note.md").exists()

    # 6. Verify valid markdown file modification still works
    res = append_to_existing_note("Daily.md", "New valid line")
    assert res["success"] is True
    assert "New valid line" in valid_note.read_text(encoding="utf-8")


# =====================================================================
# 3. Path Confinement Engine Bypass Vectors
# =====================================================================

def test_confine_blocks_filesystem_roots_and_traversal(tmp_path):
    trusted_ws = tmp_path / "trusted_ws"
    trusted_ws.mkdir()
    add_trusted_workspace(trusted_ws)

    try:
        # Direct root drives
        with pytest.raises(PermissionError):
            confine("C:\\", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine("C:", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine("/", trusted_roots=[trusted_ws])

        # Traversal out of trusted roots
        with pytest.raises(PermissionError):
            confine(r"C:\Windows\..\Users", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine(str(trusted_ws / ".." / "external_dir"), trusted_roots=[trusted_ws])

        # UNC paths
        with pytest.raises(PermissionError):
            confine(r"\\localhost\c$", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine(r"\\127.0.0.1\share", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine("//server/share", trusted_roots=[trusted_ws])

        # Long path / device prefixes
        with pytest.raises(PermissionError):
            confine(r"\\?\C:\Windows", trusted_roots=[trusted_ws])
        with pytest.raises(PermissionError):
            confine(r"\\.\COM1", trusted_roots=[trusted_ws])

        # NTFS Alternate Data Streams (ADS)
        with pytest.raises(PermissionError):
            confine(str(trusted_ws / "file.md::$DATA"), trusted_roots=[trusted_ws], allow_create=True)
        with pytest.raises(PermissionError):
            confine(str(trusted_ws / "test.txt:stream"), trusted_roots=[trusted_ws], allow_create=True)

        # DOS Reserved Device Names (Windows)
        dos_names = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "CON.txt", "sub/nul.json", "aux.log"]
        for d_name in dos_names:
            with pytest.raises(PermissionError):
                confine(str(trusted_ws / d_name), trusted_roots=[trusted_ws], allow_create=True)

        # 8.3 short names pointing outside root
        with pytest.raises(PermissionError):
            confine(r"C:\PROGRA~1", trusted_roots=[trusted_ws])

    finally:
        remove_trusted_workspace(trusted_ws)


def test_confine_blocks_escaping_junctions(tmp_path):
    """
    On Windows NTFS, creating a directory junction (mklink /J) pointing outside
    the workspace must be detected and rejected during canonical path resolution.
    """
    ws = tmp_path / "workspace"
    ws.mkdir()
    external_secret = tmp_path / "external_secret"
    external_secret.mkdir()
    secret_file = external_secret / "passwords.txt"
    secret_file.write_text("classified", encoding="utf-8")

    link_path = ws / "junction_escape"

    # Create junction via cmd mklink /J
    cmd = ["cmd", "/c", "mklink", "/J", str(link_path), str(external_secret)]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode != 0:
        pytest.skip(f"mklink /J not supported in this environment: {proc.stderr}")

    add_trusted_workspace(ws)
    try:
        # Accessing files through the escaping junction must raise PermissionError
        with pytest.raises(PermissionError):
            confine(link_path / "passwords.txt", kind="workspace", trusted_roots=[ws])
    finally:
        remove_trusted_workspace(ws)


# =====================================================================
# 4. Poisoned Git Repository Configuration Attacks
# =====================================================================

def test_poisoned_git_config_never_executes_arbitrary_commands(tmp_path):
    """
    A cloned repository with malicious config options:
    - core.fsmonitor = cmd /c echo pwned > pwned_fsmonitor.txt
    - diff.external = cmd /c echo pwned > pwned_diff.txt
    - malicious hooks in .git/hooks/
    must have these overrides neutralized by hardened flags (-c core.fsmonitor=false --no-ext-diff -c core.hooksPath=NUL).
    """
    repo_dir = tmp_path / "poisoned_repo"
    repo_dir.mkdir()

    # Initialize a clean git repo
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True)

    test_file = repo_dir / "app.py"
    test_file.write_text("print('v1')\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True)

    # Poison .git/config
    marker_fsmonitor = repo_dir / "pwned_fsmonitor.txt"
    marker_diff = repo_dir / "pwned_diff.txt"
    marker_hook = repo_dir / "pwned_hook.txt"

    fsmonitor_cmd = f"cmd /c echo x > \"{marker_fsmonitor}\""
    diff_cmd = f"cmd /c echo x > \"{marker_diff}\""

    subprocess.run(["git", "config", "core.fsmonitor", fsmonitor_cmd], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "diff.external", diff_cmd], cwd=str(repo_dir), check=True)

    # Add a malicious hook
    hooks_dir = repo_dir / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_file = hooks_dir / "pre-commit"
    hook_file.write_text(f"cmd /c echo x > \"{marker_hook}\"\n", encoding="utf-8")

    # Make a change so diff is non-empty
    test_file.write_text("print('v2')\n", encoding="utf-8")

    # Run git inspection via git_tools
    add_trusted_workspace(repo_dir)
    try:
        status_res = get_git_status(str(repo_dir))
        diff_res = get_git_diff_summary(str(repo_dir))

        assert status_res["success"] is True
        assert diff_res["success"] is True

        # Crucial security invariants: none of the malicious commands ran
        assert not marker_fsmonitor.exists(), "core.fsmonitor exploit payload executed!"
        assert not marker_diff.exists(), "diff.external exploit payload executed!"
        assert not marker_hook.exists(), "Malicious hook executed!"

    finally:
        remove_trusted_workspace(repo_dir)


# =====================================================================
# 5. Dual-Workspace Database Isolation
# =====================================================================

def test_dual_workspace_db_isolation(tmp_path):
    """
    Two distinct workspaces containing identical relative paths (e.g. app/core.py)
    must resolve to distinct SQLite index database paths and maintain isolated state.
    """
    ws1 = tmp_path / "workspace_one"
    ws2 = tmp_path / "workspace_two"
    (ws1 / "app").mkdir(parents=True)
    (ws2 / "app").mkdir(parents=True)

    (ws1 / "app" / "core.py").write_text("def unique_symbol_one(): pass\n", encoding="utf-8")
    (ws2 / "app" / "core.py").write_text("def unique_symbol_two(): pass\n", encoding="utf-8")

    db1_path = resolve_index_db_path(ws1)
    db2_path = resolve_index_db_path(ws2)

    assert db1_path != db2_path, "Different workspaces must not share the same index DB path."

    add_trusted_workspace(ws1)
    add_trusted_workspace(ws2)
    try:
        storage1 = IndexStorage(root_dir=ws1)
        storage2 = IndexStorage(root_dir=ws2)

        indexer1 = IncrementalIndexer(workspace_root=ws1, storage=storage1)
        indexer2 = IncrementalIndexer(workspace_root=ws2, storage=storage2)

        indexer1.index_workspace()
        indexer2.index_workspace()

        with storage1.get_connection() as conn1:
            cur1 = conn1.cursor()
            cur1.execute("SELECT name FROM symbols WHERE name = 'unique_symbol_one'")
            assert cur1.fetchone() is not None
            cur1.execute("SELECT name FROM symbols WHERE name = 'unique_symbol_two'")
            assert cur1.fetchone() is None, "Cross-workspace symbol leak into workspace 1!"

        with storage2.get_connection() as conn2:
            cur2 = conn2.cursor()
            cur2.execute("SELECT name FROM symbols WHERE name = 'unique_symbol_two'")
            assert cur2.fetchone() is not None
            cur2.execute("SELECT name FROM symbols WHERE name = 'unique_symbol_one'")
            assert cur2.fetchone() is None, "Cross-workspace symbol leak into workspace 2!"

    finally:
        remove_trusted_workspace(ws1)
        remove_trusted_workspace(ws2)
