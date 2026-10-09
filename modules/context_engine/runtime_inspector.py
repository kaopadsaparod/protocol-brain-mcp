"""
Runtime & Service Inspector for Protocol Brain Context Engine.
Provides development environment awareness, runtime versions, masked environment inspection,
and local listening development service discovery.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

# Keywords that trigger strict secret redaction
SENSITIVE_KEYWORDS = {
    "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "AUTH",
    "CREDENTIAL", "PRIVATE", "SIGNATURE", "APIKEY", "API_KEY",
    "CERT", "SSH", "BEARER", "DATABASE_URL", "CONNECTION_STRING",
}


def is_sensitive_key(key: str) -> bool:
    """Checks if an environment variable key indicates sensitive secrets."""
    upper = key.upper()
    return any(keyword in upper for keyword in SENSITIVE_KEYWORDS)


def get_cli_version(cmd: str) -> Optional[str]:
    """Retrieves CLI tool version safely without throwing."""
    if not shutil.which(cmd):
        return None
    try:
        out = subprocess.check_output(
            [cmd, "--version"],
            stderr=subprocess.STDOUT,
            timeout=2,
            text=True,
        ).strip()
        # Take first line
        return out.splitlines()[0] if out else None
    except Exception:
        return "installed (version unknown)"


def inspect_runtime(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Captures complete runtime environment snapshot with strict secret redaction.
    """
    try:
        from ..security.confine import confine
        root = confine(workspace_root or Path.cwd(), kind="workspace")
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid workspace root: {e}",
            "actionable_hint": "Specify a valid workspace path within trusted workspaces.",
        }

    # Python virtualenv detection
    venv_path = os.environ.get("VIRTUAL_ENV")
    in_venv = bool(venv_path)
    if not in_venv:
        # Check if workspace contains .venv
        if (root / ".venv").exists():
            venv_path = str(root / ".venv")
            in_venv = True

    # Tool versions
    tools_versions = {
        "python": sys.version.split()[0],
        "node": get_cli_version("node"),
        "npm": get_cli_version("npm"),
        "git": get_cli_version("git"),
        "docker": get_cli_version("docker"),
        "uv": get_cli_version("uv"),
        "ruff": get_cli_version("ruff"),
    }

    # Selected safe environment variables (with strict masking)
    safe_env_whitelist = [
        "VIRTUAL_ENV", "NODE_ENV", "PYTHONPATH", "OS", "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS", "SHELL", "COMSPEC", "TERM", "LANG", "TZ",
    ]
    env_snapshot: Dict[str, str] = {}
    for k in safe_env_whitelist:
        if k in os.environ:
            env_snapshot[k] = os.environ[k]

    # Mask any other variables that might be inspected
    masked_env_count = 0
    for k, v in os.environ.items():
        if is_sensitive_key(k):
            masked_env_count += 1

    # Format concise markdown snapshot
    lines = [
        "# 🖥️ Development Runtime Snapshot",
        f"- **OS:** {platform.system()} {platform.release()} ({platform.machine()})",
        f"- **Python Executable:** `{sys.executable}` ({tools_versions['python']})",
        f"- **Virtual Environment:** {'Active (`' + venv_path + '`)' if in_venv else 'None (Global/System)'}",
        f"- **Node.js:** `{tools_versions['node'] or 'Not installed'}`",
        f"- **Git:** `{tools_versions['git'] or 'Not installed'}`",
        f"- **Docker:** `{tools_versions['docker'] or 'Not installed'}`",
        f"- **Secrets Redaction:** {masked_env_count} sensitive environment keys safely protected",
    ]

    return {
        "success": True,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
        },
        "python": {
            "version": tools_versions["python"],
            "executable": sys.executable,
            "virtual_env": venv_path if in_venv else None,
            "is_venv_active": in_venv,
        },
        "tools": {k: v for k, v in tools_versions.items() if v is not None},
        "environment": env_snapshot,
        "masked_secrets_count": masked_env_count,
        "runtime_markdown": "\n".join(lines),
    }


KNOWN_SERVICES: Dict[int, str] = {
    3000: "React / Next.js Dev Server",
    5173: "Vite Dev Server",
    8000: "FastAPI / Django / Python Backend",
    8080: "Webpack Dev Server / HTTP Alt",
    5000: "Flask Dev Server",
    4200: "Angular CLI",
    5432: "PostgreSQL Database",
    3306: "MySQL Database",
    6379: "Redis Cache Server",
    27017: "MongoDB Database",
    8765: "Protocol Brain MCP Server",
}


def inspect_local_services(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Discovers active listening network services on localhost and identifies dev servers,
    backends, and database instances.
    """
    if workspace_root:
        try:
            from ..security.confine import confine
            confine(workspace_root, kind="workspace")
        except Exception as e:
            return {
                "success": False,
                "error": f"Invalid workspace root: {e}",
                "actionable_hint": "Specify a valid workspace path within trusted workspaces.",
            }

    discovered_services: List[Dict[str, Any]] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        return {
            "success": False,
            "error": f"Permission denied inspecting network sockets: {e}",
            "actionable_hint": "Run with standard user permissions or check firewall policies.",
        }

    seen_ports = set()

    for conn in connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            port = conn.laddr.port
            ip = conn.laddr.ip

            # Check loopback or all interfaces
            if ip in ("127.0.0.1", "0.0.0.0", "::1", "::"):
                if port in seen_ports:
                    continue
                seen_ports.add(port)

                pid = conn.pid
                proc_name = "unknown"
                cmdline = ""
                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        from ..security.sanitizer import format_safe_process_summary
                        cmdline = format_safe_process_summary(p.cmdline(), fallback_name=proc_name)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                service_desc = KNOWN_SERVICES.get(port, "Custom Service")
                discovered_services.append({
                    "port": port,
                    "host": ip,
                    "pid": pid,
                    "process_name": proc_name,
                    "command_summary": cmdline,
                    "service_type": service_desc,
                })

    # Sort by port
    discovered_services.sort(key=lambda s: s["port"])

    # Markdown format
    lines = ["# 🌐 Active Local Services & Dev Servers"]
    if not discovered_services:
        lines.append("No active listening ports detected on loopback interfaces.")
    else:
        for s in discovered_services:
            lines.append(
                f"- **Port {s['port']}** (`{s['host']}`): **{s['service_type']}** "
                f"(PID {s['pid']} `{s['process_name']}`)"
            )

    return {
        "success": True,
        "total_listening_services": len(discovered_services),
        "services": discovered_services,
        "summary_markdown": "\n".join(lines),
    }
