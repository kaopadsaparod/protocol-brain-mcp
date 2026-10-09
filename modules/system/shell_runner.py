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
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import psutil

from ..config import get_trusted_workspaces, load_config
from ..logger import logger
from ..security import redact_secrets

# Metacharacters that could enable command chaining, redirection, or backgrounding
FORBIDDEN_OPERATORS: Set[str] = set("&|<>^\n\r`;$()")

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


def is_trusted_binary_location(exe_path: Path, cwd_path: Path) -> bool:
    """
    Validates that the executable resides in a legitimate system/runtime path,
    and prevents PATH hijacking from Downloads, Temp, or unvetted directories.
    """
    try:
        resolved = exe_path.resolve(strict=True)
    except (OSError, RuntimeError):
        resolved = exe_path.resolve()
    resolved_cwd = cwd_path.resolve()

    # Reject if directly inside CWD root (must not execute arbitrary binary in project root)
    if resolved.parent == resolved_cwd:
        return False

    parts_lower = [p.lower() for p in resolved.parts]
    for untrusted in ("downloads", "temp", "tmp"):
        if untrusted in parts_lower:
            return False

    # Check approved system roots and runtimes
    approved_roots = [
        Path(os.environ.get("SystemRoot", "C:\\Windows")).resolve(),
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")).resolve(),
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")).resolve(),
        Path(os.environ.get("ProgramData", "C:\\ProgramData")).resolve(),
        Path(sys.base_prefix).resolve(),
        Path(sys.prefix).resolve(),
        Path.home() / "AppData",
    ]

    # Only include .venv directories if they reside inside configured trusted workspaces
    trusted_workspaces = get_trusted_workspaces()
    if is_path_under_roots(resolved_cwd, trusted_workspaces):
        approved_roots.append(resolved_cwd / ".venv")
    for tw in trusted_workspaces:
        approved_roots.append(tw / ".venv")

    for root in approved_roots:
        if root in resolved.parents or resolved == root:
            return True

    return False


def resolve_executable(binary_name: str, cwd_path: Path, allowed_prefixes: List[str]) -> Optional[Path]:
    """
    Safely resolves the executable in system PATH or local .venv without executing rogue files in CWD.
    Enforces that the resolved binary is in a trusted system/runtime location, resolves symlinks,
    and validates against allowed prefixes.
    """
    clean_name = binary_name.strip().strip("\"'")

    # On Windows, map npm -> npm.cmd and npx -> npx.cmd
    if clean_name.lower() == "npm":
        clean_name = "npm.cmd"
    elif clean_name.lower() == "npx":
        clean_name = "npx.cmd"

    resolved_path: Optional[Path] = None

    # Check project venv ONLY if cwd_path is strictly within a trusted workspace
    trusted_workspaces = get_trusted_workspaces()
    is_cwd_trusted = is_path_under_roots(cwd_path, trusted_workspaces)

    if is_cwd_trusted:
        if clean_name.lower() in ("python", "python.exe"):
            venv_py = cwd_path / ".venv" / "Scripts" / "python.exe"
            if venv_py.exists() and venv_py.is_file():
                try:
                    real_venv = venv_py.resolve()
                    if is_path_under_roots(real_venv, [cwd_path / ".venv"]) and is_trusted_binary_location(real_venv, cwd_path):
                        resolved_path = real_venv
                except (OSError, RuntimeError):
                    pass

        elif clean_name.lower() in ("pytest", "pytest.exe"):
            venv_pytest = cwd_path / ".venv" / "Scripts" / "pytest.exe"
            if venv_pytest.exists() and venv_pytest.is_file():
                try:
                    real_pytest = venv_pytest.resolve()
                    if is_path_under_roots(real_pytest, [cwd_path / ".venv"]) and is_trusted_binary_location(real_pytest, cwd_path):
                        resolved_path = real_pytest
                except (OSError, RuntimeError):
                    pass
            if not resolved_path:
                venv_py = cwd_path / ".venv" / "Scripts" / "python.exe"
                if venv_py.exists() and venv_py.is_file():
                    try:
                        real_venv = venv_py.resolve()
                        if is_path_under_roots(real_venv, [cwd_path / ".venv"]) and is_trusted_binary_location(real_venv, cwd_path):
                            resolved_path = real_venv
                    except (OSError, RuntimeError):
                        pass

    # Resolve strictly using system PATH if not found in verified .venv
    if not resolved_path:
        system_path = os.environ.get("PATH", "")
        resolved_str = shutil.which(clean_name, path=system_path)
        if not resolved_str and clean_name.lower() in ("pytest", "pytest.exe"):
            resolved_str = shutil.which("python", path=system_path) or sys.executable

        if not resolved_str:
            return None

        try:
            resolved_path = Path(resolved_str).resolve()
        except (OSError, RuntimeError):
            return None

    # Reject if binary is in an untrusted location (e.g. CWD root, Temp, Downloads)
    if not is_trusted_binary_location(resolved_path, cwd_path):
        logger.warning(f"Executable '{resolved_path}' rejected: untrusted binary location.")
        return None

    # Check against allowed prefixes
    base_stem = resolved_path.stem.lower()
    allowed_stems = {p.lower().split(".")[0] for p in allowed_prefixes}
    # If pytest was resolved via python.exe, verify either python or pytest is allowed
    if base_stem not in allowed_stems and not (clean_name.lower().startswith("pytest") and "pytest" in allowed_stems):
        logger.warning(f"Executable '{base_stem}' not in allowed list: {allowed_stems}")
        return None

    return resolved_path


def check_dangerous_flags(binary_name: str, args: List[str]) -> Optional[str]:
    """
    Detects and rejects arbitrary execution flags like python -c or node -e.
    Flags for git are evaluated case-sensitively so 'git -C' is preserved.
    """
    bin_lower = Path(binary_name).name.lower()
    flag_denylist = DANGEROUS_FLAGS.get(bin_lower) or DANGEROUS_FLAGS.get(Path(binary_name).stem.lower())
    if not flag_denylist:
        return None

    is_git = bin_lower.startswith("git")
    for arg in args:
        for dangerous in flag_denylist:
            if is_git:
                if arg == dangerous or arg.startswith(f"{dangerous}="):
                    return f"Disallowed flag '{arg}' detected for binary '{binary_name}'."
            else:
                arg_lower = arg.lower().strip()
                if arg_lower == dangerous or arg_lower.startswith(f"{dangerous}="):
                    return f"Disallowed flag '{arg}' detected for binary '{binary_name}'."
    return None


def _kill_process_tree(pid: int) -> None:
    """Recursively terminates a process and all its children using psutil."""
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except (psutil.NoSuchProcess, Exception):
                pass
        parent.kill()
    except (psutil.NoSuchProcess, Exception):
        pass


def _bounded_stream_reader(
    stream,
    max_store_bytes: int,
    flood_threshold: int,
    output_container: Dict[str, Any],
    key: str,
    stop_event: threading.Event,
    flood_event: threading.Event,
) -> None:
    """
    Reads from a subprocess pipe in discrete chunks up to max_store_bytes in memory.
    If total bytes generated exceed flood_threshold, signals flood_event to terminate
    runaway DoS processes.
    """
    buf = bytearray()
    total_bytes = 0
    chunk_size = 4096

    try:
        while not stop_event.is_set():
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            chunk_len = len(chunk)
            total_bytes += chunk_len

            if len(buf) < max_store_bytes:
                remaining_space = max_store_bytes - len(buf)
                buf.extend(chunk[:remaining_space])

            if total_bytes > flood_threshold:
                flood_event.set()
                break
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
        output_container[key] = bytes(buf)
        output_container[f"{key}_truncated"] = total_bytes > max_store_bytes
        output_container[f"{key}_total_bytes"] = total_bytes


def run_safe_command(
    command: str,
    cwd: Optional[str] = None,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Executes a shell command with defense-in-depth security:
    - shell=False with argument vector parsing
    - Rejects shell operators (&, |, <, >, ^, %, newline, etc.)
    - Strict allowlist and flags checking
    - Constrained CWD within trusted_workspaces
    - Capped timeout with recursive process tree termination
    - Bounded streaming reader to prevent OOM / RAM exhaustion DoS
    - Truncated output to prevent context window explosion
    """
    if not command or not command.strip():
        return {
            "success": False,
            "error": "Empty command string provided.",
            "actionable_hint": "Provide a valid non-empty command.",
            "exit_code": -1,
        }

    cfg = load_config()

    # 1. Parse argument vector and strip outer quotes
    try:
        raw_argv = shlex.split(command.strip(), posix=False)
        argv = [
            t[1:-1] if (len(t) >= 2 and ((t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")))) else t
            for t in raw_argv
        ]
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse command arguments: {e}",
            "actionable_hint": "Ensure quotes are properly balanced.",
            "exit_code": -1,
        }

    if not argv:
        return {"success": False, "error": "No executable specified.", "exit_code": -1}

    # 2. Check dangerous arbitrary evaluation flags (-c, -e)
    flag_err = check_dangerous_flags(argv[0], argv[1:])
    if flag_err:
        return {
            "success": False,
            "error": flag_err,
            "actionable_hint": "Arbitrary inline evaluation flags (-c, -e) are blocked to prevent prompt injection.",
            "exit_code": -1,
        }

    # 3. Reject shell metacharacters
    if contains_forbidden_operators(command):
        return {
            "success": False,
            "error": "Shell operators or metacharacters (&, |, <, >, ^, %, newline, etc.) are strictly forbidden.",
            "actionable_hint": "Execute a single command with discrete arguments without chaining, backgrounding, or file redirection.",
            "exit_code": -1,
        }

    # 3. Check CWD boundaries against trusted_workspaces
    trusted_workspaces = get_trusted_workspaces(cfg)
    work_dir = Path(cwd).resolve() if cwd else (trusted_workspaces[0] if trusted_workspaces else Path.cwd().resolve())
    if not work_dir.exists():
        return {
            "success": False,
            "error": f"Working directory '{cwd}' does not exist.",
            "actionable_hint": "Verify the target folder exists.",
            "exit_code": -1,
        }

    if not is_path_under_roots(work_dir, trusted_workspaces):
        return {
            "success": False,
            "error": f"Working directory '{work_dir}' is outside trusted workspaces.",
            "actionable_hint": f"Run commands only within trusted workspaces: {[str(r) for r in trusted_workspaces]}. Add vetted directories to config.local.json under 'trusted_workspaces'.",
            "exit_code": -1,
        }

    # 4. Resolve binary from system PATH or venv
    allowed_prefixes = cfg.get("allowed_shell_prefixes", ["git", "python", "npm", "npx", "pytest", "node", "ruff"])
    exe_path = resolve_executable(argv[0], work_dir, allowed_prefixes)
    if not exe_path:
        return {
            "success": False,
            "error": f"Binary '{argv[0]}' is either not found in system PATH, outside trusted locations, or not in the allowed shell prefixes.",
            "actionable_hint": f"Allowed prefixes are: {allowed_prefixes}. Binaries placed directly in CWD, Downloads, or Temp are blocked for safety.",
            "exit_code": -1,
        }

    # 5. Dangerous flags check (inspect flags immediately before any execution or capability evaluation)
    flag_err = check_dangerous_flags(exe_path.name, argv[1:])
    if flag_err:
        return {
            "success": False,
            "error": flag_err,
            "actionable_hint": "Arbitrary inline evaluation flags (-c, -e) are blocked to prevent prompt injection.",
            "exit_code": -1,
        }

    # 6. Capability-based policy evaluation
    from ..security import evaluate_command_capability
    is_cap_allowed, req_cap, cap_reason = evaluate_command_capability(argv, cwd=work_dir)
    if not is_cap_allowed:
        return {
            "success": False,
            "error": f"Operation rejected by capability policy: {cap_reason}",
            "actionable_hint": f"The '{req_cap}' capability is disabled. Enable it in config.json or config.local.json under 'capabilities'.",
            "exit_code": -1,
        }

    # 7. Timeout ceiling
    max_timeout = int(cfg.get("safe_command_timeout_seconds", 60))
    enforced_timeout = min(max(1, timeout_seconds), max_timeout)

    # 8. Execute with shell=False and bounded streaming readers
    if argv[0].lower().startswith("pytest") and exe_path.name.lower().startswith("python"):
        cmd_list = [str(exe_path), "-m", "pytest", *argv[1:]]
    else:
        cmd_list = [str(exe_path), *argv[1:]]

    max_bytes = int(cfg.get("max_output_bytes", 16384))
    # Flood ceiling: terminate process if output volume exceeds 4x max_output_bytes (min 64KB)
    flood_threshold = max(max_bytes * 4, 65536)

    try:
        proc = subprocess.Popen(
            cmd_list,
            cwd=str(work_dir),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stream_results: Dict[str, Any] = {
            "stdout": b"",
            "stdout_truncated": False,
            "stdout_total_bytes": 0,
            "stderr": b"",
            "stderr_truncated": False,
            "stderr_total_bytes": 0,
        }
        stop_event = threading.Event()
        flood_event = threading.Event()

        t_stdout = threading.Thread(
            target=_bounded_stream_reader,
            args=(proc.stdout, max_bytes, flood_threshold, stream_results, "stdout", stop_event, flood_event),
            daemon=True,
        )
        t_stderr = threading.Thread(
            target=_bounded_stream_reader,
            args=(proc.stderr, max_bytes, flood_threshold, stream_results, "stderr", stop_event, flood_event),
            daemon=True,
        )
        t_stdout.start()
        t_stderr.start()

        timed_out = False
        flooded = False
        t_start = time.perf_counter()

        while True:
            ret = proc.poll()
            if ret is not None:
                break

            if flood_event.is_set():
                flooded = True
                break

            elapsed = time.perf_counter() - t_start
            if elapsed > enforced_timeout:
                timed_out = True
                break

            time.sleep(0.02)

        if timed_out or flooded:
            stop_event.set()
            _kill_process_tree(proc.pid)
            try:
                proc.kill()
            except Exception:
                pass

        t_stdout.join(timeout=1.0)
        t_stderr.join(timeout=1.0)

        if timed_out:
            logger.warning(f"Process {proc.pid} timed out after {enforced_timeout}s. Process tree terminated.")
            return {
                "success": False,
                "error": f"Command timed out after {enforced_timeout} seconds. Process tree terminated.",
                "actionable_hint": "Optimize the command or consider if long-running processes should be started as background services.",
                "exit_code": -1,
            }

        if flooded:
            logger.warning(f"Process {proc.pid} exceeded flood limit ({flood_threshold} bytes). Process tree terminated.")
            return {
                "success": False,
                "error": f"Command output exceeded safety limit ({flood_threshold} bytes). Process tree terminated to prevent DoS/OOM.",
                "actionable_hint": "Filter or paginate output to produce smaller log volume.",
                "exit_code": -1,
            }

        # 9. Decode with fallback encodings
        def decode_bytes(b: bytes) -> str:
            for enc in ["utf-8", "cp874", "cp1252", "latin-1"]:
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    continue
            return b.decode("utf-8", errors="replace")

        stdout_str = decode_bytes(stream_results["stdout"])
        stderr_str = decode_bytes(stream_results["stderr"])

        # 10. Output truncation by max_log_lines and byte ceiling
        max_lines = int(cfg.get("max_log_lines", 50))

        def truncate_output(text: str, was_truncated: bool) -> str:
            if len(text) > max_bytes or was_truncated:
                text = text[:max_bytes] + "\n... [Output truncated: byte limit reached]"
            lines = text.splitlines()
            if len(lines) > max_lines:
                text = "\n".join(lines[:max_lines]) + f"\n... [Output truncated: {len(lines) - max_lines} lines omitted]"
            return text

        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "command_executed": " ".join(cmd_list),
            "stdout": truncate_output(redact_secrets(stdout_str), stream_results.get("stdout_truncated", False)),
            "stderr": truncate_output(redact_secrets(stderr_str), stream_results.get("stderr_truncated", False)),
        }
    except Exception as e:
        logger.error(f"Error executing command '{cmd_list}': {e}")
        return {
            "success": False,
            "error": f"Execution failed: {e}",
            "actionable_hint": "Check binary dependencies or system execution permissions.",
            "exit_code": -1,
        }
