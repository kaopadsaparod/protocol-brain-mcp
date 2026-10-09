"""
Logging configuration for Protocol Brain MCP.
CRITICAL: Never output logs to stdout because stdout is strictly reserved
for MCP JSON-RPC protocol messages. All logs must go to stderr or a file.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "protocol_brain.log"

logger = logging.getLogger("protocol_brain")
logger.setLevel(logging.DEBUG)

# Avoid duplicate handlers if reloaded
if not logger.handlers:
    # Handler 1: stderr (safe for MCP stdio transport)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    # Handler 2: File handler with rotation (DEBUG level)
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        pass
