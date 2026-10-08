"""
Unit tests for Context Engine Impact Analyzer & Git Intelligence.
Verifies blast radius calculation (find_impact), test mapping (find_relevant_tests),
and git history retrieval (git_context).
"""

from pathlib import Path

import pytest

from modules.context_engine.impact_analyzer import find_impact, find_relevant_tests, git_context


@pytest.fixture
def repo_workspace(tmp_path: Path):
    """Sets up a mock workspace with inter-connected components and tests."""
    core_dir = tmp_path / "core"
    core_dir.mkdir()

    # Database connection manager
    db_file = core_dir / "db.py"
    db_file.write_text(
        "class ConnectionPool:\n"
        "    def acquire(self):\n"
        "        return 'conn'\n"
        "    def release(self, conn):\n"
        "        pass\n",
        encoding="utf-8",
    )

    # API handler that uses db
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    api_file = api_dir / "handler.py"
    api_file.write_text(
        "from core.db import ConnectionPool\n\n"
        "def handle_request():\n"
        "    pool = ConnectionPool()\n"
        "    conn = pool.acquire()\n"
        "    pool.release(conn)\n",
        encoding="utf-8",
    )

    # Test file for db
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "test_db.py"
    test_file.write_text(
        "from core.db import ConnectionPool\n\n"
        "def test_pool_acquire():\n"
        "    pool = ConnectionPool()\n"
        "    assert pool.acquire() == 'conn'\n",
        encoding="utf-8",
    )

    return tmp_path


def test_find_impact_blast_radius(repo_workspace):
    """Verifies finding references, dependent files, and risk level assessment."""
    res = find_impact(
        symbol_name="ConnectionPool",
        file_path="core/db.py",
        workspace_root=str(repo_workspace),
    )

    assert res["success"] is True
    assert res["symbol_name"] == "ConnectionPool"
    assert res["total_references"] >= 2  # Used in handler.py and test_db.py
    assert res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert len(res["affected_tests"]) >= 1


def test_find_relevant_tests(repo_workspace):
    """Verifies matching test files and targeted CLI command generation."""
    res = find_relevant_tests(
        target_file_or_symbol="core/db.py",
        workspace_root=str(repo_workspace),
    )

    assert res["success"] is True
    assert res["total_tests_found"] >= 1
    assert any("test_db.py" in cmd for cmd in res["recommended_commands"])


def test_git_context_empty_or_clean(repo_workspace):
    """Verifies git context behaves safely even if workspace is not a git repo or on errors."""
    res = git_context(workspace_root=str(repo_workspace))
    # In a non-git tmp_path, it will safely return an error dict with actionable hint
    assert "success" in res
    if not res["success"]:
        assert "actionable_hint" in res


def test_find_impact_empty_symbol():
    """Empty symbol should fail gracefully."""
    res = find_impact(symbol_name="")
    assert res["success"] is False
    assert "actionable_hint" in res
