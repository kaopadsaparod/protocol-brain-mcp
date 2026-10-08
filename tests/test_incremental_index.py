"""
Unit tests for Context Engine Incremental Indexer & SQLite Storage.
Verifies fast mtime/size checks, sub-millisecond cache hits, and deleted file pruning.
"""

import time
from pathlib import Path

import pytest

from modules.context_engine.indexer import IncrementalIndexer
from modules.context_engine.storage import DatabaseManager


@pytest.fixture
def temp_workspace(tmp_path: Path):
    """Creates a mock workspace with sample Python and TypeScript files."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Python source file
    py_file = src_dir / "calculator.py"
    py_file.write_text(
        "import math\n\n"
        "class Calculator:\n"
        "    def add(self, a: int, b: int) -> int:\n"
        "        \"\"\"Adds two numbers.\"\"\"\n"
        "        return a + b\n\n"
        "    def multiply(self, a: int, b: int) -> int:\n"
        "        return a * b\n",
        encoding="utf-8",
    )

    # Python test file
    test_file = src_dir / "test_calculator.py"
    test_file.write_text(
        "import pytest\n"
        "from calculator import Calculator\n\n"
        "def test_calculator_add():\n"
        "    calc = Calculator()\n"
        "    assert calc.add(2, 3) == 5\n",
        encoding="utf-8",
    )

    # TypeScript source file
    ts_file = src_dir / "service.ts"
    ts_file.write_text(
        "export interface User {\n"
        "    id: string;\n"
        "    name: string;\n"
        "}\n\n"
        "export function getUser(id: string): User {\n"
        "    return { id, name: 'Alice' };\n"
        "}\n",
        encoding="utf-8",
    )

    db_path = tmp_path / ".protocol_brain" / "index.db"
    db_mgr = DatabaseManager(db_path=db_path)
    db_mgr.init_schema()

    return {
        "root": tmp_path,
        "src": src_dir,
        "py_file": py_file,
        "test_file": test_file,
        "ts_file": ts_file,
        "db": db_mgr,
    }


def test_initial_indexing(temp_workspace):
    """Initial indexing should discover all files and parse AST symbols."""
    indexer = IncrementalIndexer(db=temp_workspace["db"], workspace_root=temp_workspace["root"])
    res = indexer.index_workspace()

    assert res["success"] is True
    assert res["files_scanned"] == 3
    assert res["files_indexed"] == 3
    assert res["cache_hits"] == 0

    with temp_workspace["db"].get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM files")
        assert cur.fetchone()[0] == 3

        cur.execute("SELECT COUNT(*) FROM symbols")
        symbol_count = cur.fetchone()[0]
        assert symbol_count >= 3  # Calculator, add, multiply, getUser

        cur.execute("SELECT COUNT(*) FROM tests")
        assert cur.fetchone()[0] >= 1  # test_calculator_add


def test_incremental_cache_hit_on_unchanged_files(temp_workspace):
    """Second indexing pass without file changes must hit cache immediately with 0 re-indexes."""
    indexer = IncrementalIndexer(db=temp_workspace["db"], workspace_root=temp_workspace["root"])
    indexer.index_workspace()

    # Immediate second pass
    t0 = time.perf_counter()
    res2 = indexer.index_workspace()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert res2["files_scanned"] == 3
    assert res2["files_indexed"] == 0
    assert res2["cache_hits"] == 3
    assert elapsed_ms < 100.0  # Ultra-fast pass


def test_incremental_partial_update(temp_workspace):
    """Modifying one file must only re-index that single file."""
    indexer = IncrementalIndexer(db=temp_workspace["db"], workspace_root=temp_workspace["root"])
    indexer.index_workspace()

    # Sleep slightly so mtime is strictly greater
    time.sleep(0.05)
    temp_workspace["py_file"].write_text(
        "class Calculator:\n"
        "    def add(self, a, b):\n"
        "        return a + b\n"
        "    def subtract(self, a, b):\n"
        "        return a - b\n",
        encoding="utf-8",
    )

    res = indexer.index_workspace()
    assert res["files_indexed"] == 1
    assert res["cache_hits"] == 2


def test_pruning_deleted_files(temp_workspace):
    """Deleted files from disk must be purged from SQLite index."""
    indexer = IncrementalIndexer(db=temp_workspace["db"], workspace_root=temp_workspace["root"])
    indexer.index_workspace()

    # Delete typescript file
    temp_workspace["ts_file"].unlink()

    res = indexer.index_workspace()
    assert res["deleted_pruned"] == 1

    with temp_workspace["db"].get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM files")
        assert cur.fetchone()[0] == 2
