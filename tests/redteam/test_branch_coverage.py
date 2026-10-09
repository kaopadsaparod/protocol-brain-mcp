"""
Tests specifically designed to exercise boundary conditions, fallback paths,
and defensive decision branches across modules.security and modules.system.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.config import DEFAULT_CONFIG
from modules.security.confine import confine, is_root_drive
from modules.security.policy import (
    evaluate_command_capability,
    evaluate_tool_capability,
)
from modules.system.git_tools import get_git_diff_summary, get_git_status
from modules.system.shell_runner import (
    is_trusted_binary_location,
    resolve_executable,
    run_safe_command,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ==============================================================================
# 1. modules.security.confine branch tests
# ==============================================================================

def test_confine_vault_kind(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    note = vault_dir / "my_note.md"
    note.write_text("# Note", encoding="utf-8")

    with patch("modules.security.confine.get_vault_path", return_value=vault_dir):
        # Normal vault file
        res = confine("my_note.md", kind="vault")
        assert res == note.resolve()

        # Hidden segment in vault kind must be rejected
        with pytest.raises(PermissionError, match="hidden or restricted segments"):
            confine(".obsidian/plugins/test/main.js", kind="vault")

        with pytest.raises(PermissionError, match="hidden or restricted segments"):
            confine("subfolder/.hidden/secret.md", kind="vault")


def test_confine_allow_create_false(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    with patch("modules.security.confine.get_trusted_workspaces", return_value=[ws]):
        with pytest.raises(FileNotFoundError, match="does not exist"):
            confine("nonexistent_file_abc.txt", kind="workspace", allow_create=False, base_dir=ws)


def test_confine_is_root_drive_exception():
    class BrokenPath:
        def resolve(self):
            raise RuntimeError("Filesystem failure")

    assert is_root_drive(BrokenPath()) is False


def test_confine_resolve_oserror():
    orig_resolve = Path.resolve

    def mock_resolve(self, *args, **kwargs):
        if "failing_target" in str(self):
            raise OSError("Resolution failure")
        return orig_resolve(self, *args, **kwargs)

    with patch.object(Path, "resolve", autospec=True, side_effect=mock_resolve):
        with pytest.raises(PermissionError, match="Failed to resolve path"):
            confine("failing_target.txt")


def test_confine_points_to_root_drive():
    with pytest.raises(PermissionError, match="Filesystem root"):
        confine("C:\\")


def test_confine_device_names_and_unc_and_ads():
    with pytest.raises(PermissionError, match="reserved device name"):
        confine("CON")

    with pytest.raises(PermissionError, match="reserved device name"):
        confine("subdir/NUL.txt")

    with pytest.raises(PermissionError, match="UNC path"):
        confine(r"\\server\share\file.txt")

    with pytest.raises(PermissionError, match="Drive-relative"):
        confine("C:file.txt")

    with pytest.raises(PermissionError, match="Alternate Data Stream"):
        confine("file.txt::$DATA")

    # Explicit trusted_roots
    res = confine("README.md", trusted_roots=[PROJECT_ROOT])
    assert res == (PROJECT_ROOT / "README.md").resolve()


# ==============================================================================
# 2. modules.security.policy branch tests
# ==============================================================================

def test_policy_empty_and_default_tools():
    allowed, cap, msg = evaluate_command_capability([])
    assert allowed is False
    assert cap == "none"
    assert "Empty argument vector" in msg

    allowed, cap, msg = evaluate_tool_capability("read_vault_index")
    assert allowed is True
    assert cap == "none"
    assert "Tool permitted" in msg

def test_policy_release_port_allowed():
    custom_cfg = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "process_termination": True,
        },
    }
    with patch("modules.security.policy.load_config", return_value=custom_cfg):
        allowed, cap, reason = evaluate_tool_capability("release_port")
        assert allowed is True
        assert cap == "process_termination"

    # Default should be rejected
    allowed, cap, _ = evaluate_tool_capability("release_port")
    assert allowed is False
    assert cap == "process_termination"


def test_policy_git_flags_outside_workspace(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    # Git with -C pointing outside workspace
    allowed, cap, _ = evaluate_command_capability(["git", "-C", str(outside), "status"])
    assert allowed is False
    assert cap == "system_control"

    # Git with -C<path> attached
    allowed, cap, _ = evaluate_command_capability(["git", f"-C{str(outside)}", "status"])
    assert allowed is False
    assert cap == "system_control"

    # Git with --git-dir pointing outside workspace
    allowed, cap, _ = evaluate_command_capability(["git", "--git-dir", str(outside / ".git"), "status"])
    assert allowed is False
    assert cap == "system_control"

    # Git with --git-dir= attached
    allowed, cap, _ = evaluate_command_capability(["git", f"--git-dir={str(outside / '.git')}", "status"])
    assert allowed is False
    assert cap == "system_control"

    # Git with --work-tree pointing outside workspace
    allowed, cap, _ = evaluate_command_capability(["git", "--work-tree", str(outside), "status"])
    assert allowed is False
    assert cap == "system_control"


def test_policy_git_subcommand_branches():
    # Git command with no subcommand (e.g. git --version or bare git)
    allowed, cap, _ = evaluate_command_capability(["git"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "--version"])
    assert allowed is True
    assert cap == "git_read"

    # Git tag query flags vs mutation
    allowed, cap, _ = evaluate_command_capability(["git", "tag", "-l"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "tag", "--sort=-v:refname"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "tag", "-d", "v1.0"])
    assert allowed is False
    assert cap == "git_write"

    allowed, cap, _ = evaluate_command_capability(["git", "tag", "v2.0"])
    assert allowed is False
    assert cap == "git_write"

    # Git branch query flags vs mutation
    allowed, cap, _ = evaluate_command_capability(["git", "branch", "-a"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "branch", "--show-current"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "branch", "-D", "feature"])
    assert allowed is False
    assert cap == "git_write"

    allowed, cap, _ = evaluate_command_capability(["git", "branch", "new-branch"])
    assert allowed is False
    assert cap == "git_write"

    # Git remote query vs mutation
    allowed, cap, _ = evaluate_command_capability(["git", "remote", "-v"])
    assert allowed is True
    assert cap == "git_read"

    allowed, cap, _ = evaluate_command_capability(["git", "remote", "add", "origin", "https://github.com/org/repo.git"])
    assert allowed is False
    assert cap == "git_write"

    allowed, cap, _ = evaluate_command_capability(["git", "remote", "rm", "origin"])
    assert allowed is False
    assert cap == "git_write"

    # Other write subcommands
    for sub in ["push", "commit", "reset", "rebase", "cherry-pick"]:
        allowed, cap, _ = evaluate_command_capability(["git", sub])
        assert allowed is False
        assert cap == "git_write"


def test_policy_pytest_variations(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    # Custom plugin -p requires system_control
    allowed, cap, _ = evaluate_command_capability(["pytest", "-p", "evil_plugin"])
    assert allowed is False
    assert cap == "system_control"

    allowed, cap, _ = evaluate_command_capability(["pytest", "-p=evil_plugin"])
    assert allowed is False
    assert cap == "system_control"

    allowed, cap, _ = evaluate_command_capability(["pytest", "-c", "custom.ini"])
    assert allowed is False
    assert cap == "system_control"

    # --rootdir outside workspace
    allowed, cap, _ = evaluate_command_capability(["pytest", "--rootdir", str(outside)])
    assert allowed is False
    assert cap == "system_control"

    allowed, cap, _ = evaluate_command_capability(["pytest", f"--rootdir={str(outside)}"])
    assert allowed is False
    assert cap == "system_control"

    # Target path outside workspace
    allowed, cap, _ = evaluate_command_capability(["pytest", str(outside / "test_evil.py")])
    assert allowed is False
    assert cap == "system_control"

    # Allowed pytest execution when capability disabled
    custom_cfg = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "run_tests": False,
        },
    }
    with patch("modules.security.policy.load_config", return_value=custom_cfg):
        allowed, cap, _ = evaluate_command_capability(["pytest", "tests/test_basic.py"])
        assert allowed is False
        assert cap == "run_tests"

    # Pytest with options -k, -m, -o
    allowed, cap, _ = evaluate_command_capability(["pytest", "-k", "foo", "-m", "smoke", "-o", "addopts=", "tests/test_basic.py"])
    assert allowed is True
    assert cap == "run_tests"

    # Pytest with system_control enabled
    cfg_sys = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "system_control": True,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_sys):
        allowed, cap, _ = evaluate_command_capability(["pytest", "-p", "custom_plugin"])
        assert allowed is True
        assert cap == "system_control"


def test_policy_ruff_variations(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    # Ruff config outside workspace
    allowed, cap, _ = evaluate_command_capability(["ruff", "-c", str(outside / "ruff.toml")])
    assert allowed is False
    assert cap == "system_control"

    allowed, cap, _ = evaluate_command_capability(["ruff", f"--config={str(outside / 'ruff.toml')}"])
    assert allowed is False
    assert cap == "system_control"

    # Ruff target outside workspace
    allowed, cap, _ = evaluate_command_capability(["ruff", "check", str(outside / "code.py")])
    assert allowed is False
    assert cap == "system_control"

    # Ruff format / --fix requires git_write
    allowed, cap, _ = evaluate_command_capability(["ruff", "format"])
    assert allowed is False
    assert cap == "git_write"

    allowed, cap, _ = evaluate_command_capability(["ruff", "check", "--fix"])
    assert allowed is False
    assert cap == "git_write"

    # When git_write enabled
    cfg_git_write = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "git_write": True,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_git_write):
        allowed, cap, _ = evaluate_command_capability(["ruff", "format"])
        assert allowed is True
        assert cap == "git_write"

    # Ruff check when run_tests is disabled
    cfg_no_test = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "run_tests": False,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_no_test):
        allowed, cap, _ = evaluate_command_capability(["ruff", "check"])
        assert allowed is False
        assert cap == "run_tests"


def test_policy_python_variations():
    # python -m pytest with disabled run_tests
    cfg_no_test = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "run_tests": False,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_no_test):
        allowed, cap, _ = evaluate_command_capability(["python", "-m", "pytest"])
        assert allowed is False
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "unittest"])
        assert allowed is False
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff"])
        assert allowed is False
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "tests/test_x.py"])
        assert allowed is False
        assert cap == "run_tests"

    # python -m ruff --fix requires git_write
    allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff", "check", "--fix"])
    assert allowed is False
    assert cap == "git_write"

    allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff", "format"])
    assert allowed is False
    assert cap == "git_write"

    # python -m ruff with git_write=True
    cfg_write = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "git_write": True,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_write):
        allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff", "check", "--fix"])
        assert allowed is True
        assert cap == "git_write"

    # Fallback to system_control
    allowed, cap, _ = evaluate_command_capability(["notepad.exe"])
    assert allowed is False
    assert cap == "system_control"

    cfg_sys_ctrl = {
        **DEFAULT_CONFIG,
        "capabilities": {
            **DEFAULT_CONFIG["capabilities"],
            "system_control": True,
        },
    }
    with patch("modules.security.policy.load_config", return_value=cfg_sys_ctrl):
        allowed, cap, _ = evaluate_command_capability(["notepad.exe"])
        assert allowed is True
        assert cap == "system_control"


# ==============================================================================
# 3. modules.system.shell_runner branch tests
# ==============================================================================

def test_shell_runner_syntax_and_empty():
    # Empty string
    res = run_safe_command("")
    assert res["success"] is False
    assert "Empty command" in res["error"]

    res = run_safe_command("   ")
    assert res["success"] is False
    assert "Empty command" in res["error"]

    # Unbalanced quotes
    res = run_safe_command('python "unclosed_string')
    assert res["success"] is False
    assert "Failed to parse command arguments" in res["error"]


def test_shell_runner_blocked_extensions_and_tools():
    # .cmd / .bat
    res = run_safe_command("run.cmd arg1")
    assert res["success"] is False
    assert "blocked to prevent cmd.exe command injection" in res["error"]

    res = run_safe_command("script.bat")
    assert res["success"] is False
    assert "blocked to prevent cmd.exe command injection" in res["error"]

    # npm / npx
    res = run_safe_command("npm test")
    assert res["success"] is False
    assert "Execution of Windows batch script 'npm' is blocked" in res["error"]

    res = run_safe_command("npx lint")
    assert res["success"] is False
    assert "Execution of Windows batch script 'npx' is blocked" in res["error"]


def test_shell_runner_untrusted_locations(tmp_path):
    # Executable in Downloads or Temp is rejected
    downloads_exe = Path.home() / "Downloads" / "fake_git.exe"
    assert is_trusted_binary_location(downloads_exe, tmp_path) is False

    temp_exe = Path(r"C:\Windows\Temp\tool.exe")
    assert is_trusted_binary_location(temp_exe, tmp_path) is False


def test_shell_runner_resolve_executable_venv(tmp_path):
    ws = tmp_path / "my_project"
    scripts = ws / ".venv" / "Scripts"
    scripts.mkdir(parents=True)
    fake_py = scripts / "python.exe"
    fake_py.write_text("binary", encoding="utf-8")

    with patch("modules.system.shell_runner.get_trusted_workspaces", return_value=[ws]):
        with patch("modules.system.shell_runner.is_trusted_binary_location", return_value=True):
            resolved = resolve_executable("python", cwd_path=ws, allowed_prefixes=["python"])
            assert resolved == fake_py.resolve()


# ==============================================================================
# 4. modules.system.git_tools branch tests
# ==============================================================================

def test_git_tools_out_of_bounds_repo():
    outside = Path("C:/Windows/System32/bogus_git_repo")

    # Outside trusted workspaces returns error dict
    res_status = get_git_status(repo_path_str=str(outside))
    assert res_status["success"] is False
    assert "unconfined" in res_status["error"].lower()

    res_diff = get_git_diff_summary(repo_path_str=str(outside))
    assert res_diff["success"] is False
    assert "unconfined" in res_diff["error"].lower()


def test_git_tools_binary_resolution_and_non_repo(tmp_path):
    from modules.system.git_tools import find_git_binary, is_git_repo

    # is_git_repo on non-existent folder
    assert is_git_repo(tmp_path / "not_a_repo") is False

    # find_git_binary with shutil.which returning None
    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            assert find_git_binary() is None


# ==============================================================================
# 5. modules.system.notification exception tests
# ==============================================================================

def test_notification_subprocess_exception():
    import subprocess
    from modules.system.notification import send_windows_notification

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=5)):
        res = send_windows_notification("title", "msg")
        assert res["success"] is False
        assert "error" in res


# ==============================================================================
# 6. modules.system.shell_runner flags and execution branches
# ==============================================================================

def test_shell_runner_dangerous_flags_and_prefixes():
    from modules.system.shell_runner import check_dangerous_flags

    # Dangerous arbitrary evaluation flags
    res = run_safe_command("python -c pass")
    assert res["success"] is False
    assert "Disallowed flag '-c'" in res["error"]

    assert check_dangerous_flags("node", ["-e", "something"]) is not None

    # Non-existent or disallowed binary
    res = run_safe_command("unknown_tool_xyz_123")
    assert res["success"] is False
    assert "not found in system PATH" in res["error"] or "outside trusted" in res["error"]


# ==============================================================================
# 7. modules.system.port_killer branches
# ==============================================================================

def test_port_killer_validation_and_capabilities():
    from modules.system.port_killer import free_port, list_listening_ports, is_port_listening

    # Invalid port range (< 1024 or > 65535 or non-int)
    res = free_port(80)
    assert res["success"] is False
    assert "Invalid port" in res["error"]

    res = free_port(70000)
    assert res["success"] is False
    assert "Invalid port" in res["error"]

    res = free_port("not_a_port")
    assert res["success"] is False
    assert "Invalid port" in res["error"]

    # Capability disabled
    res = free_port(3000, bypass_capability=False)
    assert res["success"] is False
    assert "capability" in res["error"].lower()

    # Listing listening ports returns list
    ports = list_listening_ports()
    assert isinstance(ports, list)

    # is_port_listening returns bool
    assert isinstance(is_port_listening(9), bool)


def test_port_killer_free_and_ancestor_protection():
    import os
    from modules.system.port_killer import free_port

    # Port with no listening process is already free
    res = free_port(59999, bypass_capability=True)
    assert res["success"] is True
    assert "already free" in res["message"]

    # Protect ancestor PID
    with patch("modules.system.port_killer.get_protected_pids", return_value={12345}):
        class FakeConn:
            status = "LISTEN"
            laddr = type("Addr", (), {"port": 4000, "ip": "127.0.0.1"})()
            pid = 12345

        with patch("psutil.net_connections", return_value=[FakeConn()]):
            res = free_port(4000, bypass_capability=True)
            assert res["success"] is False
            assert "ancestor or self" in res["error"]


def test_port_killer_denylist_protection():
    from modules.system.port_killer import free_port

    class FakeConn:
        status = "LISTEN"
        laddr = type("Addr", (), {"port": 4001, "ip": "127.0.0.1"})()
        pid = 9999

    class FakeProc:
        def create_time(self):
            return 100.0
        def name(self):
            return "explorer.exe"

    with patch("psutil.net_connections", return_value=[FakeConn()]):
        with patch("psutil.Process", return_value=FakeProc()):
            res = free_port(4001, bypass_capability=True)
            assert res["success"] is False
            assert "protected in the system denylist" in res["error"]


# ==============================================================================
# 8. Mutation Sensitivity & Rigor Suite (kills surviving mutants)
# ==============================================================================

def test_mutation_sensitivity_confine(tmp_path):
    from modules.security.confine import (
        add_trusted_workspace,
        remove_trusted_workspace,
        _EXTRA_TRUSTED_WORKSPACES,
    )

    # 1. Null, empty string and whitespace must raise ValueError
    with pytest.raises(ValueError):
        confine(None)
    with pytest.raises(ValueError):
        confine("")
    with pytest.raises(ValueError):
        confine("   ")

    # 2. allow_create defaults to False: non-existent file must raise FileNotFoundError
    with pytest.raises(FileNotFoundError):
        confine("definitely_nonexistent_file_987654.txt")

    # 3. remove_trusted_workspace on present vs non-present path
    custom_ws = tmp_path / "extra_workspace"
    custom_ws.mkdir()
    add_trusted_workspace(custom_ws)
    assert custom_ws.resolve() in _EXTRA_TRUSTED_WORKSPACES
    remove_trusted_workspace(custom_ws)
    assert custom_ws.resolve() not in _EXTRA_TRUSTED_WORKSPACES
    # Safe to call again on non-present path
    remove_trusted_workspace(custom_ws)

    # 4. kind='workspace' vs kind='any' or kind='file'
    note_file = PROJECT_ROOT / "README.md"
    assert confine("README.md", kind="workspace") == note_file.resolve()
    assert confine("README.md", kind="any") == note_file.resolve()
    assert confine("README.md", kind="file") == note_file.resolve()

    # 5. Workspace kind strictly excludes vault note if vault is outside workspaces
    separate_vault = tmp_path / "separate_vault"
    separate_vault.mkdir()
    vault_note = separate_vault / "note.md"
    vault_note.write_text("vault content", encoding="utf-8")
    isolated_ws = tmp_path / "isolated_ws"
    isolated_ws.mkdir()

    with patch("modules.security.confine._EXTRA_TRUSTED_WORKSPACES", []):
        with patch("modules.security.confine.get_vault_path", return_value=separate_vault):
            with patch("modules.security.confine.get_trusted_workspaces", return_value=[isolated_ws]):
                assert confine(vault_note, kind="any") == vault_note.resolve()
                with pytest.raises(PermissionError):
                    confine(vault_note, kind="workspace")


def test_mutation_sensitivity_policy():
    # 1. Missing 'capabilities' key in config must evaluate to strict defaults
    with patch("modules.security.policy.load_config", return_value={}):
        allowed, cap, _ = evaluate_tool_capability("release_port")
        assert allowed is False
        assert cap == "process_termination"

        allowed, cap, _ = evaluate_command_capability(["git", "push"])
        assert allowed is False
        assert cap == "git_write"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "pytest"])
        assert allowed is True
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff"])
        assert allowed is True
        assert cap == "run_tests"

    # 2. Empty capabilities dictionary in config must fallback to required defaults
    with patch("modules.security.policy.load_config", return_value={"capabilities": {}}):
        allowed, cap, _ = evaluate_tool_capability("release_port")
        assert allowed is False
        assert cap == "process_termination"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "pytest"])
        assert allowed is True
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "-m", "ruff"])
        assert allowed is True
        assert cap == "run_tests"

        allowed, cap, _ = evaluate_command_capability(["python", "tests/conftest.py"])
        assert allowed is True
        assert cap == "run_tests"

    # 3. Path resolution failure branches in pytest/ruff must return False
    orig_resolve = Path.resolve

    def selective_resolve(self, *args, **kwargs):
        if "foo" in str(self) or "config.toml" in str(self):
            raise OSError("Disk failure")
        return orig_resolve(self, *args, **kwargs)

    with patch.object(Path, "resolve", autospec=True, side_effect=selective_resolve):
        allowed, cap, _ = evaluate_command_capability(["pytest", "--rootdir", "foo"])
        assert allowed is False
        assert cap == "system_control"

        allowed, cap, _ = evaluate_command_capability(["pytest", "tests/foo.py"])
        assert allowed is False
        assert cap == "system_control"

        allowed, cap, _ = evaluate_command_capability(["ruff", "-c", "config.toml"])
        assert allowed is False
        assert cap == "system_control"

        allowed, cap, _ = evaluate_command_capability(["ruff", "check", "foo.py"])
        assert allowed is False
        assert cap == "system_control"

    # Additional policy capability default checks to kill mutants
    with patch("modules.security.policy.load_config", return_value={"capabilities": {}}):
        allowed, cap, _ = evaluate_command_capability(["git", "diff", "--output=foo.txt"])
        assert allowed is False
        assert cap == "git_write"

        allowed, cap, _ = evaluate_command_capability(["pytest", "tests/test_x.py"])
        assert allowed is True
        assert cap == "run_tests"


def test_mutation_sensitivity_shell_runner(tmp_path):
    # 1. Non-existent working directory must fail
    res = run_safe_command("git status", cwd=str(tmp_path / "non_existent_folder_xyz"))
    assert res["success"] is False
    assert res["exit_code"] == -1
    assert "does not exist" in res["error"]

    # 2. Quotes stripping for both single and double quotes
    with patch("modules.system.shell_runner.subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0
        mock_proc.stdout = None
        mock_proc.stderr = None
        run_safe_command("python 'tests/test_single.py' \"tests/test_double.py\"")
        executed_cmd = mock_popen.call_args[0][0]
        assert executed_cmd[1] == "tests/test_single.py"
        assert executed_cmd[2] == "tests/test_double.py"

    # 3. Disallowed executable prefix rejection
    assert resolve_executable("curl", cwd_path=PROJECT_ROOT, allowed_prefixes=["python", "git"]) is None
    assert resolve_executable("powershell", cwd_path=PROJECT_ROOT, allowed_prefixes=["python", "git"]) is None

    # 4. Binary directly in project root is rejected
    root_binary = PROJECT_ROOT / "evil_tool.exe"
    assert is_trusted_binary_location(root_binary, PROJECT_ROOT) is False

    # 5. Popen shell=False enforcement
    with patch("modules.system.shell_runner.subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.poll.return_value = 0
        mock_proc.returncode = 0
        mock_proc.stdout = None
        mock_proc.stderr = None
        run_safe_command("git status")
        assert mock_popen.call_args[1].get("shell") is False

    # 6. Process spawn error handling
    with patch("modules.system.shell_runner.subprocess.Popen", side_effect=RuntimeError("Process spawn error")):
        res = run_safe_command("git status")
        assert res["success"] is False
        assert "Process spawn error" in res["error"]

    # 7. Resolving pytest in venv
    ws_pytest = tmp_path / "ws_pytest"
    scripts_dir = ws_pytest / ".venv" / "Scripts"
    scripts_dir.mkdir(parents=True)
    pytest_exe = scripts_dir / "pytest.exe"
    pytest_exe.write_text("pytest_bin", encoding="utf-8")
    with patch("modules.system.shell_runner.get_trusted_workspaces", return_value=[ws_pytest]):
        with patch("modules.system.shell_runner.is_trusted_binary_location", return_value=True):
            resolved = resolve_executable("pytest", cwd_path=ws_pytest, allowed_prefixes=["pytest"])
            assert resolved == pytest_exe.resolve()

    # 8. Un-truncated output must not include truncation notice
    with patch("modules.system.shell_runner.subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0
        mock_proc.stdout = None
        mock_proc.stderr = None
        res_clean = run_safe_command("git status")
        assert "... [Output truncated" not in res_clean["stdout"]
        assert "... [Output truncated" not in res_clean["stderr"]

    # 9. Verify reader threads in run_safe_command have daemon=True
    threads_created = []
    import threading
    orig_thread = threading.Thread
    def spy_thread(*args, **kwargs):
        t = orig_thread(*args, **kwargs)
        threads_created.append(t)
        return t

    with patch("modules.system.shell_runner.threading.Thread", side_effect=spy_thread):
        with patch("modules.system.shell_runner.subprocess.Popen"):
            run_safe_command("git status")
    assert len(threads_created) >= 2
    assert all(t.daemon is True for t in threads_created)
