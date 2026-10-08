"""
Centralized configuration loader for Protocol Brain.
Supports config.local.json overrides over config.json.
"""

import json
from pathlib import Path
from typing import Any, Dict

from .logger import logger

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"
LOCAL_CONFIG_FILE = BASE_DIR / "config.local.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "vault_path": "D:\\vault",
    "libreoffice_path": "C:\\Program Files\\LibreOffice\\program\\soffice.com",
    "allowed_roots": [
        "C:\\Users",
        "D:\\",
        "F:\\",
    ],
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
}


def load_config() -> Dict[str, Any]:
    """
    Loads configuration with local override support:
    1. Base defaults
    2. Overwritten by config.json
    3. Overwritten by config.local.json (if present)
    """
    config = dict(DEFAULT_CONFIG)

    # 1. Base config.json
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                config.update(loaded)
        except Exception as e:
            logger.warning(f"Failed to parse {CONFIG_FILE.name}: {e}")

    # 2. Local override config.local.json
    if LOCAL_CONFIG_FILE.exists():
        try:
            with open(LOCAL_CONFIG_FILE, "r", encoding="utf-8") as f:
                local_loaded = json.load(f)
                config.update(local_loaded)
                logger.info(f"Loaded local configuration overrides from {LOCAL_CONFIG_FILE.name}")
        except Exception as e:
            logger.warning(f"Failed to parse {LOCAL_CONFIG_FILE.name}: {e}")

    return config
