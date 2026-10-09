"""
Hierarchical configuration loader for Protocol Brain.
Resolution precedence (highest to lowest):
1. Runtime CLI arguments / Explicit overrides
2. Environment Variables (PROTOCOL_BRAIN_*)
3. Local overrides (config.local.json)
4. Base defaults (config.json)
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .logger import logger

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"
LOCAL_CONFIG_FILE = BASE_DIR / "config.local.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "vault_path": None,
    "libreoffice_path": None,
    "host": "127.0.0.1",
    "port": 8000,
    "auth_token": None,
    "allowed_roots": [
        "C:\\Users",
        "D:\\",
        "F:\\",
    ],
    "trusted_workspaces": [
        str(BASE_DIR),
    ],
    "capabilities": {
        "git_read": True,
        "git_write": False,
        "run_tests": True,
        "package_install": False,
        "system_control": False,
        "process_termination": False,
    },
    "allowed_shell_prefixes": [
        "git",
        "python",
        "npm",
        "npx",
        "pytest",
        "node",
        "ruff",
    ],
    "safe_command_timeout_seconds": 60,
    "max_log_lines": 50,
    "max_output_bytes": 16384,
    "context_engine": {
        "index_db_path": None,
        "default_token_budget": 4000,
        "max_files": 15,
        "max_symbols": 30,
        "max_depth": 2,
    },
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merges override into base dictionary without wiping sibling keys.
    """
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


def load_config(cli_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Loads configuration following strict hierarchical precedence:
    1. CLI overrides
    2. Environment variables
    3. config.local.json (deep merged)
    4. config.json (deep merged)
    5. DEFAULT_CONFIG
    """
    config = dict(DEFAULT_CONFIG)

    # 1. Base config.json
    custom_cfg_env = os.environ.get("PROTOCOL_BRAIN_CONFIG")
    target_config = Path(custom_cfg_env) if custom_cfg_env else CONFIG_FILE

    if target_config.exists():
        try:
            with open(target_config, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                config = deep_merge(config, loaded)
        except Exception as e:
            logger.warning(f"Failed to parse config file {target_config}: {e}")

    # 2. Local override config.local.json
    if LOCAL_CONFIG_FILE.exists():
        try:
            with open(LOCAL_CONFIG_FILE, "r", encoding="utf-8") as f:
                local_loaded = json.load(f)
                config = deep_merge(config, local_loaded)
        except Exception as e:
            logger.warning(f"Failed to parse {LOCAL_CONFIG_FILE.name}: {e}")

    # 3. Environment Variables
    if os.environ.get("PROTOCOL_BRAIN_VAULT"):
        config["vault_path"] = os.environ["PROTOCOL_BRAIN_VAULT"]
    if os.environ.get("PROTOCOL_BRAIN_HOST"):
        config["host"] = os.environ["PROTOCOL_BRAIN_HOST"]
    if os.environ.get("PROTOCOL_BRAIN_PORT"):
        try:
            config["port"] = int(os.environ["PROTOCOL_BRAIN_PORT"])
        except ValueError:
            pass
    if os.environ.get("PROTOCOL_BRAIN_AUTH_TOKEN"):
        config["auth_token"] = os.environ["PROTOCOL_BRAIN_AUTH_TOKEN"]

    # 4. CLI overrides (highest precedence)
    if cli_overrides:
        clean_overrides = {k: v for k, v in cli_overrides.items() if v is not None}
        config = deep_merge(config, clean_overrides)

    return config


def get_trusted_workspaces(cfg: Optional[Dict[str, Any]] = None) -> List[Path]:
    """
    Returns resolved Path objects for all configured trusted workspaces.
    Relative paths (like '.') are strictly resolved relative to project root BASE_DIR.
    """
    if cfg is None:
        cfg = load_config()
    raw_workspaces = cfg.get("trusted_workspaces", [str(BASE_DIR)])
    resolved: List[Path] = []
    for w in raw_workspaces:
        p = Path(w)
        if not p.is_absolute():
            resolved.append((BASE_DIR / p).resolve())
        else:
            resolved.append(p.resolve())
    return resolved

