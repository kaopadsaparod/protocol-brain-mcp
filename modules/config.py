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
from typing import Any, Dict, Optional

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
        ".",
        "D:\\vault",
    ],
    "capabilities": {
        "git_read": True,
        "git_write": False,
        "run_tests": True,
        "package_install": False,
        "system_control": False,
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


def load_config(cli_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Loads configuration following strict hierarchical precedence.
    """
    config = dict(DEFAULT_CONFIG)

    # 1. Base config.json
    custom_cfg_env = os.environ.get("PROTOCOL_BRAIN_CONFIG")
    target_config = Path(custom_cfg_env) if custom_cfg_env else CONFIG_FILE

    if target_config.exists():
        try:
            with open(target_config, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            logger.warning(f"Failed to parse config file {target_config}: {e}")

    # 2. Local override config.local.json
    if LOCAL_CONFIG_FILE.exists():
        try:
            with open(LOCAL_CONFIG_FILE, "r", encoding="utf-8") as f:
                local_loaded = json.load(f)
                config.update(local_loaded)
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
        for k, v in cli_overrides.items():
            if v is not None:
                config[k] = v

    return config
