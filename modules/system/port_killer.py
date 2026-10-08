"""
Port Killer and Process Guard Module for Windows.
Prevents EADDRINUSE errors by safely terminating orphaned processes.
"""

import os
from typing import Any, Dict, List

import psutil

from ..logger import logger


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


def free_port(port: int) -> Dict[str, Any]:
    """
    Finds and terminates any process listening on the specified port.
    Prevents EADDRINUSE errors on Windows.
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        return {
            "success": False,
            "port": port,
            "error": f"Invalid port number {port}. Port must be an integer between 1 and 65535.",
            "actionable_hint": "Provide a valid integer TCP port number, e.g. 3000 or 8000.",
        }

    killed_processes = []
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
                pid = conn.pid
                if pid and pid != os.getpid():
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                        proc.terminate()
                        proc.wait(timeout=3)
                        killed_processes.append({"pid": pid, "name": proc_name})
                        logger.info(f"Terminated PID {pid} ({proc_name}) on port {port}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                        try:
                            proc.kill()
                            killed_processes.append({"pid": pid, "name": proc_name, "status": "force_killed"})
                            logger.info(f"Force-killed PID {pid} ({proc_name}) on port {port}")
                        except Exception as kill_err:
                            logger.error(f"Failed to kill PID {pid} on port {port}: {kill_err}")
                            return {
                                "success": False,
                                "port": port,
                                "error": f"Failed to kill PID {pid}: {kill_err}",
                                "actionable_hint": "Run with administrative privileges or check task manager.",
                            }

        if killed_processes:
            return {
                "success": True,
                "port": port,
                "message": f"Successfully released port {port}.",
                "terminated": killed_processes,
            }
        else:
            return {
                "success": True,
                "port": port,
                "message": f"Port {port} is already free (no listening process found).",
                "terminated": [],
                "actionable_hint": "Port is available for binding immediately.",
            }
    except Exception as e:
        logger.error(f"Error freeing port {port}: {e}")
        return {
            "success": False,
            "port": port,
            "error": str(e),
            "actionable_hint": "Ensure psutil has permission to inspect network connections.",
        }
