"""
Hardened Port Killer and Process Guard Module for Windows.
Enforces:
1. Port range validation (must be between 1024 and 65535, protecting system services).
2. Ancestor/Parent and self PID protection (cannot kill MCP server or AI client host).
3. Process name denylist (protects Ollama, Postgres, Docker, VS Code, Claude, Windows core).
4. Full process tree cleanup (terminates children recursively).
5. Robust NoSuchProcess handling (no UnboundLocalError).
6. Post-kill verification to confirm the port is genuinely free.
"""

import os
from typing import Any, Dict, List, Set

import psutil

from ..config import load_config
from ..logger import logger

# Critical services and tools that should never be terminated by port killer
DENYLIST_PROCESS_NAMES: Set[str] = {
    "code.exe",
    "claude.exe",
    "ollama.exe",
    "ollama_app.exe",
    "docker.exe",
    "dockerd.exe",
    "postgres.exe",
    "pg_ctl.exe",
    "explorer.exe",
    "system",
    "svchost.exe",
    "conhost.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "wininit.exe",
}


def get_protected_pids() -> Set[int]:
    """Returns set of PIDs containing the current server and all its ancestor processes."""
    protected: Set[int] = {os.getpid()}
    try:
        curr = psutil.Process()
        for parent in curr.parents():
            protected.add(parent.pid)
    except Exception as e:
        logger.debug(f"Error resolving parent processes: {e}")
    return protected


def is_port_listening(port: int) -> bool:
    """Checks if any TCP connection is actively listening on the port."""
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
                return True
    except Exception:
        pass
    return False


def list_listening_ports() -> List[Dict[str, Any]]:
    """List all currently listening TCP ports and associated process names."""
    results = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                pid = conn.pid
                proc_name = "Unknown"
                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                results.append({
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "pid": pid,
                    "process_name": proc_name,
                })
    except Exception as e:
        logger.error(f"Error listing listening ports: {e}")
        results.append({"error": str(e)})
    return results


def free_port(port: int, bypass_capability: bool = False) -> Dict[str, Any]:
    """
    Terminates processes listening on a user-space TCP port (1024-65535).
    Guards ancestors, enforces denylists, terminates children, and verifies availability.
    """
    if not isinstance(port, int) or port < 1024 or port > 65535:
        return {
            "success": False,
            "port": port,
            "error": f"Invalid port {port}. Port must be a user-space port between 1024 and 65535.",
            "actionable_hint": "System ports (0-1023) are protected. Target dev ports like 3000, 5173, or 8000.",
        }

    cfg = load_config()
    capabilities = cfg.get("capabilities", {})
    if not bypass_capability and not capabilities.get("process_termination", False):
        return {
            "success": False,
            "port": port,
            "error": "Process termination capability ('process_termination') is disabled in security policy.",
            "actionable_hint": "Enable 'process_termination': true in config.json or config.local.json under 'capabilities'.",
        }

    protected_pids = get_protected_pids()
    target_pids: List[int] = []

    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
                if conn.pid:
                    target_pids.append(conn.pid)
    except Exception as e:
        logger.error(f"Error inspecting net connections for port {port}: {e}")
        return {
            "success": False,
            "port": port,
            "error": f"Failed to inspect network connections: {e}",
            "actionable_hint": "Check process permissions or run with appropriate user rights.",
        }

    if not target_pids:
        return {
            "success": True,
            "port": port,
            "message": f"Port {port} is already free (no listening process found).",
            "terminated": [],
            "actionable_hint": "Port is available for binding immediately.",
        }

    terminated_processes = []

    for pid in target_pids:
        if pid in protected_pids:
            return {
                "success": False,
                "port": port,
                "error": f"Cannot release port {port}: PID {pid} is an ancestor or self of the MCP server.",
                "actionable_hint": "Do not target the port of the running AI client or server itself.",
            }

        try:
            proc = psutil.Process(pid)
            proc_create_time = proc.create_time()
            proc_name = proc.name()
        except psutil.NoSuchProcess:
            # Process already terminated naturally
            continue
        except psutil.AccessDenied:
            return {
                "success": False,
                "port": port,
                "error": f"Access denied to inspect or kill PID {pid}.",
                "actionable_hint": "The process may belong to another user or require elevated privileges.",
            }

        if proc_name.lower() in DENYLIST_PROCESS_NAMES:
            return {
                "success": False,
                "port": port,
                "error": f"Process '{proc_name}' (PID {pid}) is protected in the system denylist and cannot be terminated.",
                "actionable_hint": f"Protected processes include: {list(DENYLIST_PROCESS_NAMES)[:6]}. Stop it cleanly via its own service manager.",
            }

        # Guard against PID recycling / TOCTOU
        try:
            if not proc.is_running() or proc.create_time() != proc_create_time:
                logger.warning(f"PID {pid} was replaced or recycled (TOCTOU prevented). Skipping.")
                continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # Kill child processes first
        try:
            for child in proc.children(recursive=True):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Terminate parent
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            except psutil.NoSuchProcess:
                pass  # Successfully exited
            terminated_processes.append({"pid": pid, "name": proc_name})
            logger.info(f"Successfully killed process tree for PID {pid} ({proc_name}) on port {port}")
        except psutil.NoSuchProcess:
            terminated_processes.append({"pid": pid, "name": proc_name, "status": "exited_during_wait"})
        except Exception as kill_err:
            logger.error(f"Failed to kill PID {pid} ({proc_name}): {kill_err}")
            return {
                "success": False,
                "port": port,
                "error": f"Failed to terminate PID {pid} ({proc_name}): {kill_err}",
                "actionable_hint": "Check Windows Task Manager or permissions.",
            }

    # Verify if port is genuinely free
    if is_port_listening(port):
        return {
            "success": False,
            "port": port,
            "error": f"Port {port} is still listening after termination attempt.",
            "actionable_hint": "A new process may have immediately bound to the port, or it requires elevated admin rights.",
            "terminated": terminated_processes,
        }

    return {
        "success": True,
        "port": port,
        "message": f"Successfully released port {port}.",
        "terminated": terminated_processes,
        "verified_free": True,
    }
