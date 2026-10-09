"""
Docker Stack & Container Intelligence for Protocol Brain Context Engine.
Analyzes Compose definitions, tracks service dependencies, and diagnoses unhealthy containers
with strict secret redaction.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .runtime_inspector import is_sensitive_key


def find_compose_file(root: Path) -> Optional[Path]:
    """Finds Docker compose file in workspace."""
    candidates = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
    for c in candidates:
        p = root / c
        if p.exists():
            return p
    return None


def inspect_docker_stack(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspects Docker Compose stack architecture, dependencies, ports, and container states.
    All environment variable values are strictly masked to prevent secret leakage.
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
    compose_path = find_compose_file(root)

    if not compose_path:
        return {
            "success": True,
            "has_docker": False,
            "message": "No docker-compose.yml or compose.yaml found in workspace.",
            "services": {},
            "summary_markdown": "*(No Docker compose file detected in workspace root)*",
        }

    try:
        content = compose_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content) or {}
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse compose file: {e}",
            "actionable_hint": "Check YAML syntax in your docker-compose.yml file.",
        }

    raw_services = data.get("services", {})
    services_summary: Dict[str, Any] = {}
    tree_lines: List[str] = []

    for name, s_cfg in raw_services.items():
        if not isinstance(s_cfg, dict):
            continue

        ports = [str(p) for p in s_cfg.get("ports", [])]
        depends_on = s_cfg.get("depends_on", [])
        if isinstance(depends_on, dict):
            depends_on = list(depends_on.keys())
        elif isinstance(depends_on, str):
            depends_on = [depends_on]

        # Mask environment keys and values
        env_vars = s_cfg.get("environment", {})
        masked_env_keys = []
        if isinstance(env_vars, dict):
            for k in env_vars.keys():
                masked_env_keys.append(f"{k}=[REDACTED]" if is_sensitive_key(str(k)) else str(k))
        elif isinstance(env_vars, list):
            for item in env_vars:
                k = str(item).split("=")[0]
                masked_env_keys.append(f"{k}=[REDACTED]" if is_sensitive_key(k) else k)

        services_summary[name] = {
            "image": s_cfg.get("image") or "(build local)",
            "ports": ports,
            "depends_on": depends_on,
            "env_keys_count": len(masked_env_keys),
            "restart": s_cfg.get("restart", "no"),
        }

        dep_str = f" → depends_on: {', '.join(depends_on)}" if depends_on else ""
        port_str = f" (ports: {', '.join(ports)})" if ports else ""
        tree_lines.append(f"- **`{name}`**{port_str}{dep_str}")

    # Check live docker status if docker CLI exists
    live_status: Dict[str, str] = {}
    if shutil.which("docker"):
        try:
            ps_out = subprocess.check_output(
                ["docker", "compose", "ps", "--format", "{{.Service}}: {{.Status}}"],
                cwd=str(root),
                stderr=subprocess.DEVNULL,
                timeout=3,
                text=True,
            )
            for line in ps_out.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    live_status[parts[0].strip()] = parts[1].strip()
        except Exception:
            pass

    md_lines = [
        f"# 🐳 Docker Compose Stack: `{compose_path.name}`",
        f"- **Total Services:** {len(services_summary)}",
        "\n### 📦 Service Topology & Ports",
    ]
    for s_name, s_info in services_summary.items():
        status_badge = f" [State: {live_status.get(s_name, 'not running')}]"
        ports_text = f" (ports: {', '.join(s_info['ports'])})" if s_info['ports'] else ""
        deps_text = f" → depends on: `{', '.join(s_info['depends_on'])}`" if s_info['depends_on'] else ""
        md_lines.append(f"- **`{s_name}`**{ports_text}{deps_text}{status_badge}")

    return {
        "success": True,
        "has_docker": True,
        "compose_file": compose_path.name,
        "total_services": len(services_summary),
        "services": services_summary,
        "live_status": live_status,
        "summary_markdown": "\n".join(md_lines),
    }


def why_service_unhealthy(
    service_name: str,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Diagnoses why a Docker container service failed, exited, or is unhealthy.
    Tails error logs with strict secret masking and generates actionable fix steps.
    """
    if not service_name or not service_name.strip():
        return {
            "success": False,
            "error": "Service name cannot be empty.",
            "actionable_hint": "Specify the service name from your docker-compose.yml (e.g. 'api' or 'web').",
        }

    try:
        from ..security.confine import confine
        root = confine(workspace_root or Path.cwd(), kind="workspace")
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid workspace root: {e}",
            "actionable_hint": "Specify a valid workspace path within trusted workspaces.",
        }
    compose_path = find_compose_file(root)
    clean_name = service_name.strip()

    recent_logs = []
    if shutil.which("docker"):
        try:
            logs_out = subprocess.check_output(
                ["docker", "compose", "logs", "--tail=35", clean_name],
                cwd=str(root),
                stderr=subprocess.STDOUT,
                timeout=4,
                text=True,
            )
            from ..security.sanitizer import redact_secrets
            for raw_line in logs_out.splitlines():
                recent_logs.append(redact_secrets(raw_line))
        except subprocess.CalledProcessError as e:
            from ..security.sanitizer import redact_secrets
            recent_logs.append(redact_secrets(f"Could not read logs: {e.output}"))
        except Exception as e:
            from ..security.sanitizer import redact_secrets
            recent_logs.append(redact_secrets(f"Docker inspection error: {e}"))
    else:
        recent_logs.append("Docker CLI not available on current host PATH.")

    # Diagnostic heuristics
    logs_str = "\n".join(recent_logs).lower()
    recommendations = []
    if "connection refused" in logs_str or "could not connect" in logs_str:
        recommendations.append("Database / upstream backend connection refused. Check that dependency containers are running and listening.")
    elif "137" in logs_str or "oom" in logs_str or "killed" in logs_str:
        recommendations.append("Container was killed by OOM (Out Of Memory). Increase memory limit in compose file.")
    elif "port is already allocated" in logs_str or "address already in use" in logs_str:
        recommendations.append("Port collision detected. Use Protocol Brain `release_port` to clear the occupied host port.")
    elif "not found" in logs_str or "no such file" in logs_str:
        recommendations.append("Missing entry point script or mounted volume path. Verify file existence.")
    else:
        recommendations.append(f"Inspect container entry point and environment variables for `{clean_name}`.")

    md_lines = [
        f"# 🩺 Service Health Diagnosis: `{clean_name}`",
        f"- **Service Name:** `{clean_name}`",
        f"- **Compose File:** `{compose_path.name if compose_path else 'Not found'}`",
        "\n### 💡 Actionable Diagnosis",
    ]
    for r in recommendations:
        md_lines.append(f"- {r}")

    if recent_logs:
        md_lines.append("\n### 📜 Recent Container Logs (Filtered & Redacted)")
        md_lines.append("```text")
        md_lines.extend(recent_logs[-15:])
        md_lines.append("```")

    return {
        "success": True,
        "service_name": clean_name,
        "diagnosed_logs_count": len(recent_logs),
        "recommendations": recommendations,
        "recent_logs": recent_logs[-15:],
        "summary_markdown": "\n".join(md_lines),
    }
