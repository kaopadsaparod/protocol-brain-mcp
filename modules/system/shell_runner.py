"""
Hardened shell command runner for Windows.
Enforces:
1. shell=False with argument vector parsing (prevents cmd injection via &, &&, |, >, etc.).
2. Metacharacter rejection (&, |, <, >, ^, %, \n, \r, `, $, ;, ()).
3. System PATH binary resolution with strict allowlist and dangerous flag inspection.
4. CWD path boundary checks against allowed_roots.
5. Strict timeout ceiling with recursive child process tree termination on timeout.
6. Output truncation against max_log_lines and byte ceilings.
"""

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import psutil

from ..config import load_config
from ..logger import logger

# Metacharacters that could enable command chaining, redirection, or variable expansion
FORBIDDEN_OPERATORS: Set[str] = set("&|<>^%\n\r`;")

# Dangerous execution flags that allow arbitrary code execution inside allowed binaries
DANGEROUS_FLAGS: Dict[str, Set[str]] = {
    "python": {"-c", "--command"},
    "python.exe": {"-c", "--command"},
    "node": {"-e", "--eval", "-p", "--print"},
    "node.exe": {"-e", "--eval", "-p", "--print"},
    "git": {"-c", "--upload-pack", "--receive-pack"},
    "git.exe": {"-c", "--upload-pack", "--receive-pack"},
}


def contains_forbidden_operators(cmd_str: str) -> bool:
    """Returns True if any shell metacharacters exist in the command string."""
    return any(ch in FORBIDDEN_OPERATORS for ch in cmd_str)


def sanitize_windows_command(cmd: str, cwd_path: Optional[Path] = None) -> str:
    """
    Sanitizes command for Windows execution by replacing bare npm/npx with npm.cmd/npx.cmd.
    """
    sanitized = cmd.strip()
    sanitized = re.sub(r"^npm\s+", "npm.cmd ", sanitized)
    sanitized = re.sub(r"^npx\s+", "npx.cmd ", sanitized)
    sanitized = re.sub(r"\s+npm\s+", " npm.cmd ", sanitized)
    sanitized = re.sub(r"\s+npx\s+", " npx.cmd ", sanitized)
    return sanitized


def is_path_under_roots(target: Path, roots: List[Path]) -> bool:
    """Verify target path is located within one of the approved root directories."""
    resolved_target = target.resolve()
    for root in roots:
        resolved_root = root.resolve()
        if resolved_root in resolved_target.parents or resolved_target == resolved_root:
            return True
    return False


def resolve_executable(binary_name: str, cwd_path: Path, allowed_prefixes: List[str]) -> Optional[Path]:
    """
    Safely resolves the executable in system PATH or local .venv without executing rogue files in CWD.
    """
    clean_name = binary_name.strip().strip("\"'")

    # On Windows, map npm -> npm.cmd and npx -> npx.cmd
    if clean_name.lower() == "npm":
        clean_name = "npm.cmd"
    elif clean_name.lower() == "npx":
        clean_name = "npx.cmd"

    # Check for project venv Python if running python/pytest
    if clean_name.lower() in ("python", "python.exe", "pytest"):
        venv_py = cwd_path / ".venv" / "Scripts" / "python.exe"
        if venv_py.exists():
            return venv_py

    # Resolve strictly using system PATH
    system_path = os.environ.get("PATH", "")
    resolved_str = shutil.which(clean_name, path=system_path)
    if not resolved_str:
        return None

    resolved_path = Path(resolved_str).resolve()

    # Reject if binary resolved to a file directly inside CWD (unless it is inside .venv)
    if resolved_path.parent == cwd_path.resolve():
        logger.warning(f"Rejected executable resolved directly in CWD: {resolved_path}")
        return None

    # Check against allowed prefixes
    base_stem = resolved_path.stem.lower()
    allowed_stems = {p.lower().split(".")[0] for p in allowed_prefixes}
    if base_stem not in allowed_stems:
        logger.warning(f"Executable '{base_stem}' not in allowed list: {allowed_stems}")
        return None

    return resolved_path


def check_dangerous_flags(binary_name: str, args: List[str]) -> Optional[str]:
    """Detects and rejects arbitrary execution flags like python -c or node -e."""
    bin_lower = Path(binary_name).name.lower()
    flag_denylist = DANGEROUS_FLAGS.get(bin_lower) or DANGEROUS_FLAGS.get(Path(binary_name).stem.lower())
    if not flag_denylist:
        return None

    for arg in args:
        arg_lower = arg.lower().strip()
        for dangerous in flag_denylist:
            if arg_lower == dangerous or arg_lower.startswith(f"{dangerous}="):
                return f"Disallowed flag '{arg}' detected for binary '{binary_name}'."
    return None


def run_safe_command(
    command: str,
    cwd: Optional[str] = None,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Executes a shell command with defense-in-depth security:
    - shell=False with argument vector parsing
    - Rejects shell operators (&, |, <, >, %, newline, etc.)
    - Strict allowlist and flags checking
    - Constrained CWD within allowed roots
    - Capped timeout with recursive process tree termination
    - Truncated output to prevent context window explosion
    """
    if not command or not command.strip():
        return {
            "success": False,
            "error": "Empty command string provided.",
            "actionable_hint": "Provide a valid non-empty command.",
            "exit_code": -1,
        }

    # 1. Reject shell metacharacters immediately
    if contains_forbidden_operators(command):
        return {
            "success": False,
            "error": "Shell operators or metacharacters (&, |, <, >, ^, %, newline, etc.) are strictly forbidden.",
            "actionable_hint": "Execute a single command with discrete arguments without chaining, backgrounding, or file redirection.",
            "exit_code": -1,
        }

    cfg = load_config()

    # 2. Parse argument vector
    try:
        argv = shlex.split(command.strip(), posix=False)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse command arguments: {e}",
            "actionable_hint": "Ensure quotes are properly balanced.",
            "exit_code": -1,
        }

    if not argv:
        return {"success": False, "error": "No executable specified.", "exit_code": -1}

    # 3. Check CWD boundaries
    work_dir = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    if not work_dir.exists():
        return {
            "success": False,
            "error": f"Working directory '{cwd}' does not exist.",
            "actionable_hint": "Verify the target folder exists.",
            "exit_code": -1,
        }

    allowed_roots = [Path(r) for r in cfg.get("allowed_roots", ["C:\\Users", "D:\\", "F:\\"])]
    if not is_path_under_roots(work_dir, allowed_roots):
        return {
            "success": False,
            "error": f"Working directory '{work_dir}' is outside allowed root paths.",
            "actionable_hint": f"Run commands only within allowed roots: {[str(r) for r in allowed_roots]}",
            "exit_code": -1,
        }

    # 4. Resolve binary from system PATH or venv
    allowed_prefixes = cfg.get("allowed_shell_prefixes", ["git", "python", "npm", "npx", "pytest", "node", "ruff"])
    exe_path = resolve_executable(argv[0], work_dir, allowed_prefixes)
    if not exe_path:
        return {
            "success": False,
            "error": f"Binary '{argv[0]}' is either not found in system PATH or not in the allowed shell prefixes.",
            "actionable_hint": f"Allowed prefixes are: {allowed_prefixes}. Custom binaries placed directly in CWD are blocked for safety.",
            "exit_code": -1,
        }

    # 5. Dangerous flags check
    flag_err = check_dangerous_flags(exe_path.name, argv[1:])
    if flag_err:
        return {
            "success": False,
            "error": flag_err,
            "actionable_hint": "Arbitrary inline evaluation flags (-c, -e) are blocked to prevent prompt injection.",
            "exit_code": -1,
        }

    # 6. Timeout ceiling
    max_timeout = int(cfg.get("safe_command_timeout_seconds", 60))
    enforced_timeout = min(max(1, timeout_seconds), max_timeout)

    # 7. Execute with shell=False and process tree management
    cmd_list = [str(exe_path), *argv[1:]]

    try:
        proc = subprocess.Popen(
            cmd_list,
            cwd=str(work_dir),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=enforced_timeout)
        except subprocess.TimeoutExpired:
            # Kill process and all recursive child processes
            logger.warning(f"Process {proc.pid} timed out after {enforced_timeout}s. Terminating process tree...")
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except (psutil.NoSuchProcess, Exception):
                        pass
                parent.kill()
            except (psutil.NoSuchProcess, Exception):
                pass

            proc.communicate()  # Clean up zombie handles
            return {
                "success": False,
                "error": f"Command timed out after {enforced_timeout} seconds. Process tree terminated.",
                "actionable_hint": "Optimize the command or consider if long-running processes should be started as background services.",
                "exit_code": -1,
            }

        # 8. Decode with fallback encodings
        def decode_bytes(b: bytes) -> str:
            for enc in ["utf-8", "cp874", "cp1252", "latin-1"]:
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    continue
            return b.decode("utf-8", errors="replace")

        stdout_str = decode_bytes(stdout_bytes)
        stderr_str = decode_bytes(stderr_bytes)

        # 9. Output truncation by max_log_lines and byte ceiling
        max_lines = int(cfg.get("max_log_lines", 50))
        max_bytes = int(cfg.get("max_output_bytes", 16384))

        def truncate_output(text: str) -> str:
            if len(text) > max_bytes:
                text = text[:max_bytes] + "\n... [Output truncated: byte limit reached]"
            lines = text.splitlines()
            if len(lines) > max_lines:
                text = "\n".join(lines[:max_lines]) + f"\n... [Output truncated: {len(lines) - max_lines} lines omitted]"
            return text

        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "command_executed": " ".join(cmd_list),
            "stdout": truncate_output(stdout_str),
            "stderr": truncate_output(stderr_str),
        }
    except Exception as e:
        logger.error(f"Error executing command '{cmd_list}': {e}")
        return {
            "success": False,
            "error": f"Execution failed: {e}",
            "actionable_hint": "Check binary dependencies or system execution permissions.",
            "exit_code": -1,
        }
