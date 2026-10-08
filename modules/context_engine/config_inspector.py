"""
Config & Environment Intelligence for Protocol Brain Context Engine.
Traces environment variables across .env files, config loaders, and source code usages
with zero secret leakage.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .runtime_inspector import is_sensitive_key


def inspect_config_usage(
    variable_name: str,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Traces definition, source code references, and current runtime status of an environment variable.
    Strictly masks sensitive credentials and API secrets.
    """
    if not variable_name or not variable_name.strip():
        return {
            "success": False,
            "error": "Variable name cannot be empty.",
            "actionable_hint": "Specify an environment variable name (e.g. 'DATABASE_URL' or 'PORT').",
        }

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    var_clean = variable_name.strip()
    var_upper = var_clean.upper()

    # 1. Search config files for definition
    candidate_files = [".env", ".env.example", ".env.local", ".env.test", ".env.dev", "docker-compose.yml", "config.json"]
    defined_in: List[Dict[str, Any]] = []

    for fn in candidate_files:
        fp = root / fn
        if fp.exists():
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(text.splitlines(), start=1):
                    line_clean = line.strip()
                    if line_clean.startswith("#"):
                        continue
                    if re.search(rf"\b{re.escape(var_clean)}\b", line, re.IGNORECASE):
                        defined_in.append({"file": fn, "line": line_no})
            except Exception:
                pass

    # 2. Search code usages for references
    code_usages: List[Dict[str, Any]] = []
    # Fast regex scan over source files
    pattern = re.compile(
        rf'(?:os\.environ\.get|os\.getenv|os\.environ|process\.env|env)\s*[\.\[\(][\'"]?{re.escape(var_clean)}[\'"]?',
        re.IGNORECASE,
    )

    ignore_dirs = {".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".protocol_brain"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".py", ".ts", ".js", ".tsx", ".jsx"):
            continue
        if any(ignored in path.parts for ignored in ignore_dirs):
            continue

        try:
            rel_path = str(path.relative_to(root)).replace("\\", "/")
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for l_idx, l_content in enumerate(lines, start=1):
                if pattern.search(l_content) or var_clean in l_content:
                    # Filter out purely coincidental substring matches
                    if var_upper in l_content.upper():
                        code_usages.append({
                            "file": rel_path,
                            "line": l_idx,
                            "snippet": l_content.strip()[:80],
                        })
        except Exception:
            pass

    # 3. Check current environment status (WITH REDACTION)
    is_set = var_clean in os.environ or var_upper in os.environ
    is_secret = is_sensitive_key(var_clean)

    if is_set:
        raw_val = os.environ.get(var_clean) or os.environ.get(var_upper, "")
        masked_val = "[REDACTED_SECRET]" if is_secret else (raw_val if len(raw_val) < 40 else raw_val[:37] + "...")
    else:
        masked_val = None

    # Construct markdown summary
    md_lines = [
        f"# ⚙️ Config & Environment Trace: `{var_clean}`",
        f"- **Runtime Status:** {'✅ Set in Environment' if is_set else '❌ Unset in Environment'}",
        f"- **Security Classification:** {'🔒 Sensitive Secret (Masked)' if is_secret else '📄 Standard Configuration'}",
        f"- **Value Preview:** `{masked_val or 'None'}`",
        f"- **Definitions Found:** {len(defined_in)} config file(s)",
        f"- **Code Usages Found:** {len(code_usages)} call site(s)",
        "\n### 📝 Defined In Config Files",
    ]
    if defined_in:
        for d in defined_in:
            md_lines.append(f"- `{d['file']}:{d['line']}`")
    else:
        md_lines.append("- *(Not explicitly defined in standard .env or compose files)*")

    md_lines.append("\n### 📍 Code Usages & Injections")
    if code_usages:
        for u in code_usages[:10]:
            md_lines.append(f"- `{u['file']}:{u['line']}` → `{u['snippet']}`")
    else:
        md_lines.append("- *(No direct environment variable reads detected in source code)*")

    return {
        "success": True,
        "variable_name": var_clean,
        "is_set": is_set,
        "is_secret": is_secret,
        "masked_value": masked_val,
        "defined_in": defined_in,
        "code_usages": code_usages,
        "summary_markdown": "\n".join(md_lines),
    }
