"""
Unit tests for Diff Intelligence & Test Prediction (suggest_tests_for_change, find_changed_dependencies).
Verifies mapping diff lines to symbols, predicting relevant tests, and blast radius risk assessment.
"""

from pathlib import Path

import pytest

from modules.context_engine.diff_intelligence import (
    find_changed_dependencies,
    parse_diff_hunks,
    suggest_tests_for_change,
)


@pytest.fixture
def diff_workspace(tmp_path: Path):
    """Sets up a mock workspace with a source file and corresponding test."""
    src_dir = tmp_path / "calc"
    src_dir.mkdir()

    calc_file = src_dir / "calculator.py"
    calc_file.write_text(
        "class Calculator:\n"
        "    def add(self, a: int, b: int) -> int:\n"
        "        return a + b\n\n"
        "    def multiply(self, a: int, b: int) -> int:\n"
        "        return a * b\n",
        encoding="utf-8",
    )

    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "test_calculator.py"
    test_file.write_text(
        "from calc.calculator import Calculator\n\n"
        "def test_calculator_add():\n"
        "    calc = Calculator()\n"
        "    assert calc.add(2, 3) == 5\n\n"
        "def test_calculator_multiply():\n"
        "    calc = Calculator()\n"
        "    assert calc.multiply(2, 3) == 6\n",
        encoding="utf-8",
    )

    return tmp_path


def test_parse_diff_hunks():
    """Verifies parsing of git unified diff format."""
    mock_diff = (
        "diff --git a/calc/calculator.py b/calc/calculator.py\n"
        "index 12345..67890 100644\n"
        "--- a/calc/calculator.py\n"
        "+++ b/calc/calculator.py\n"
        "@@ -2,3 +2,3 @@\n"
        "-        return a + b\n"
        "+        return (a + b) * 1\n"
    )
    hunks = parse_diff_hunks(mock_diff)
    assert "calc/calculator.py" in hunks
    assert len(hunks["calc/calculator.py"]) == 1
    assert hunks["calc/calculator.py"][0] == (2, 4)


def test_suggest_tests_for_change(diff_workspace):
    """Verifies that modifying add() suggests test_calculator_add."""
    mock_diff = (
        "diff --git a/calc/calculator.py b/calc/calculator.py\n"
        "--- a/calc/calculator.py\n"
        "+++ b/calc/calculator.py\n"
        "@@ -2,2 +2,2 @@\n"
        "-        return a + b\n"
        "+        return (a + b)\n"
    )
    res = suggest_tests_for_change(diff=mock_diff, workspace_root=str(diff_workspace))
    assert res["success"] is True
    assert res["has_changes"] is True
    assert any(cs["name"] == "add" for cs in res["changed_symbols"])
    assert len(res["recommended_commands"]) >= 1
    assert any("test_calculator.py" in cmd for cmd in res["recommended_commands"])


def test_find_changed_dependencies(diff_workspace):
    """Verifies blast radius calculation on diff."""
    mock_diff = (
        "diff --git a/calc/calculator.py b/calc/calculator.py\n"
        "--- a/calc/calculator.py\n"
        "+++ b/calc/calculator.py\n"
        "@@ -2,2 +2,2 @@\n"
        "-        return a + b\n"
        "+        return (a + b)\n"
    )
    res = find_changed_dependencies(diff=mock_diff, workspace_root=str(diff_workspace))
    assert res["success"] is True
    assert res["has_changes"] is True
    assert "add" in res["changed_symbols"]
    assert res["risk_level"] in ("LOW", "MEDIUM", "HIGH")
