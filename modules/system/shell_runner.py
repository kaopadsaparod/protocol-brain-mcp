"""
Safe shell command runner with Windows policy adaptation and command allowlist verification.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger

CONFIG_FILE = Path(__file__).resolve().parent.parent.parent / "config.json"


def get_allowed_prefixes() -> List[str]:
    """Load allowed command prefixes from config.json."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return cfg.get("allowed_shell_prefixes", [])
        except Exception:
            pass
    return ["git", "python", "npm.cmd", "npx.cmd", "gh", "pytest", "node", "ollama", "docker"]


def sanitize_windows_command(cmd: str, cwd_path: Optional[Path] = None) -> str:
    """
    Sanitizes command for Windows PowerShell/CMD execution:
    1. Replaces 'npm' with 'npm.cmd' and 'npx' with 'npx.cmd' to avoid ExecutionPolicy errors.
    2. Auto-detects local .venv Python if available.
    """
    sanitized = cmd.strip()

    # Replace bare npm / npx
    sanitized = re.sub(r"^npm\s+", "npm.cmd ", sanitized)
    sanitized = re.sub(r"^npx\s+", "npx.cmd ", sanitized)
    sanitized = re.sub(r"\s+npm\s+", " npm.cmd ", sanitized)
    sanitized = re.sub(r"\s+npx\s+", " npx.cmd ", sanitized)

    # Check for venv python in cwd
    if cwd_path and cwd_path.exists():
        venv_py = cwd_path / ".venv" / "Scripts" / "python.exe"
        if venv_py.exists():
            if sanitized.startswith("python "):
                sanitized = f'"{venv_py}" ' + sanitized[7:]
            elif sanitized.startswith("pytest"):
                sanitized = f'"{venv_py}" -m pytest' + sanitized[6:]

    return sanitized


def is_command_allowed(command: str) -> tuple[bool, str]:
    """Check if the base command executable is in the allowed prefixes list."""
    allowed = get_allowed_prefixes()
    first_token = command.strip().split()[0].lower() if command.strip() else ""
    # Strip quotes or path
    base_name = Path(first_token.strip("\"'")).name.lower()

    for p in allowed:
        p_lower = p.lower()
        if base_name == p_lower or base_name == f"{p_lower}.exe" or base_name == f"{p_lower}.cmd":
            return True, base_name

    return False, base_name


def run_safe_command(
    command: str,
    cwd: Optional[str] = None,
    timeout_seconds: int = 60
) -> Dict[str, Any]:
    """
    Executes a shell command safely on Windows with automatic PowerShell/NPM policy adaptation
    and strict allowlist verification.
    """
    if not command or not command.strip():
        return {
            "success": False,
            "error": "Empty command provided.",
            "actionable_hint": "Provide a non-empty shell command string.",
            "exit_code": -1,
        }

    work_dir = Path(cwd).resolve() if cwd else Path.cwd()
    if not work_dir.exists():
        return {
            "success": False,
            "error": f"Working directory '{cwd}' does not exist.",
            "actionable_hint": "Check the working directory path before running commands.",
            "exit_code": -1,
        }

    adapted_cmd = sanitize_windows_command(command, work_dir)

    # Allowlist check
    allowed, base_name = is_command_allowed(adapted_cmd)
    if not allowed:
        allowed_list = get_allowed_prefixes()
        logger.warning(f"Rejected unallowed command prefix '{base_name}': {command}")
        return {
            "success": False,
            "error": f"Command '{base_name}' is not in the allowed shell prefixes list.",
            "actionable_hint": f"Allowed prefixes are: {allowed_list}. Add '{base_name}' to config.json if needed.",
            "exit_code": -1,
        }

    try:
        proc = subprocess.run(
            adapted_cmd,
            cwd=str(work_dir),
            shell=True,
            capture_output=True,
            timeout=timeout_seconds,
        )

        def decode_bytes(b: bytes) -> str:
            for enc in ["utf-8", "cp874", "cp1252", "latin-1"]:
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    continue
            return b.decode("utf-8", errors="replace")

        stdout_str = decode_bytes(proc.stdout)
        stderr_str = decode_bytes(proc.stderr)

        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "command_executed": adapted_cmd,
            "stdout": stdout_str,
            "stderr": stderr_str,
        }
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {adapted_cmd}")
        return {
            "success": False,
            "error": f"Command timed out after {timeout_seconds} seconds.",
            "actionable_hint": "Increase timeout_seconds or run the process as a background task.",
            "command_executed": adapted_cmd,
            "exit_code": -1,
        }
    except Exception as e:
        logger.error(f"Execution error for '{adapted_cmd}': {e}")
        return {
            "success": False,
            "error": str(e),
            "actionable_hint": "Check shell execution environment or command syntax.",
            "command_executed": adapted_cmd,
            "exit_code": -1,
        }
