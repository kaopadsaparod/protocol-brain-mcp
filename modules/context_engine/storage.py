"""
SQLite Persistent Storage and Connection Manager for Protocol Brain Context Engine.
Provides schema creation, thread-safe connection pooling, and resilient path resolution.
"""

import os
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from ..config import load_config

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT UNIQUE NOT NULL,
    mtime REAL NOT NULL,
    size INTEGER NOT NULL,
    hash TEXT,
    lang TEXT NOT NULL,
    total_lines INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    container TEXT,
    type TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    signature TEXT,
    docstring TEXT
);

CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    symbol TEXT,
    alias TEXT
);

CREATE TABLE IF NOT EXISTS symbol_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    target_symbol TEXT NOT NULL,
    line INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    test_name TEXT NOT NULL,
    target_symbol TEXT,
    line INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS git_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    head_commit TEXT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_id);
CREATE INDEX IF NOT EXISTS idx_imports_module ON imports(module);
CREATE INDEX IF NOT EXISTS idx_refs_target ON symbol_references(target_symbol);
CREATE INDEX IF NOT EXISTS idx_tests_target ON tests(target_symbol);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
"""


import hashlib


def resolve_index_db_path(root_dir: Optional[Path] = None) -> Path:
    """
    Resolves the persistent SQLite index path.
    1. Check config override or PROTOCOL_BRAIN_INDEX_DB environment variable
    2. Separate DB per workspace (named by hash of resolved root under %LOCALAPPDATA%/ProtocolBrain/)
    """
    cfg = load_config()
    configured_path = cfg.get("context_engine", {}).get("index_db_path") or os.environ.get("PROTOCOL_BRAIN_INDEX_DB")
    if configured_path:
        p = Path(configured_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    base_root = (root_dir or Path.cwd()).resolve()
    # Normalize path string for deterministic hashing across platforms
    norm_path = str(base_root).lower() if os.name == "nt" else str(base_root)
    path_hash = hashlib.sha256(norm_path.encode("utf-8")).hexdigest()[:16]

    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    db_dir = Path(local_app_data) / "ProtocolBrain"
    db_dir.mkdir(parents=True, exist_ok=True)
    return (db_dir / f"index_{path_hash}.db").resolve()


class ManagedConnection:
    """Wraps sqlite3.Connection to guarantee automatic closing on context exit."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self._conn.__enter__()
        return self._conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return self._conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            try:
                self._conn.close()
            except Exception:
                pass

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


class DatabaseManager:
    """Thread-safe SQLite connection and transaction manager."""

    def __init__(self, db_path: Optional[Path] = None, root_dir: Optional[Path] = None):
        self._explicit_path = db_path
        self._root_dir = root_dir
        self._lock = threading.RLock()
        self._initialized = False

    @property
    def db_path(self) -> Path:
        if self._explicit_path:
            return self._explicit_path
        return resolve_index_db_path(self._root_dir)

    def get_connection(self) -> ManagedConnection:
        """Returns a configured SQLite connection wrapped in ManagedConnection."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return ManagedConnection(conn)

    def init_schema(self):
        """Ensures the schema is initialized and WAL mode is active."""
        with self._lock:
            if not self._initialized:
                with self.get_connection() as conn:
                    conn.executescript(SCHEMA_SQL)
                self._initialized = True


# Global default database instance
db_manager = DatabaseManager()
IndexStorage = DatabaseManager
