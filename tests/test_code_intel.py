"""
Tests for Code Intelligence and Token Optimization (Happy path + Failure cases).
"""

from pathlib import Path

from modules.code_intel.error_filter import filter_build_errors
from modules.code_intel.outline import get_code_outline, read_symbol
from modules.code_intel.references import find_references

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_code_outline_python_success():
    """Happy path: Extracts symbols from Python code file."""
    res = get_code_outline(str(PROJECT_ROOT / "server.py"))
    assert res["success"] is True
    assert res["symbol_count"] > 10
    assert any(s.get("name") == "read_vault_index" for s in res["symbols"])


def test_code_outline_unsupported_extension_failure():
    """Failure Case: Unsupported file extension should return actionable guidance."""
    res = get_code_outline(str(PROJECT_ROOT / "config.json"))
    assert res["success"] is False
    assert "not supported" in res["error"]
    assert res["actionable_hint"] is not None


def test_read_symbol_success():
    """Happy path: Extracts single function without the rest of the file."""
    res = read_symbol(str(PROJECT_ROOT / "modules" / "vault" / "reader.py"), "get_vault_path")
    assert res["success"] is True
    assert res["symbol"]["name"] == "get_vault_path"
    assert "def get_vault_path" in res["symbol"]["code"]


def test_read_symbol_not_found_failure():
    """Failure Case: Symbol not found should return actionable guidance."""
    res = read_symbol(str(PROJECT_ROOT / "server.py"), "non_existent_function_xyz")
    assert res["success"] is False
    assert "not found" in res["error"].lower()
    assert "get_file_outline" in res["actionable_hint"]


def test_find_references_contextual():
    """Happy path: Contextual grep returns matching lines with context."""
    res = find_references("MCPServer", root_dir=str(PROJECT_ROOT))
    assert res["success"] is True
    assert res["total_files_matched"] > 0
    first_hit = res["results"][0]["hits"][0]
    assert "context" in first_hit


def test_filter_build_errors_noisy_log():
    """Happy path: Truncates noise and isolates errors."""
    noisy_log = (
        "Webpack bundling...\n"
        "Asset generated: bundle.js\n"
        "TS2304: Cannot find name 'UnknownVar'. at src/app.ts:12\n"
        "Finished in 4.2s\n"
    )
    res = filter_build_errors(noisy_log)
    assert res["has_errors"] is True
    assert "TS2304" in res["clean_output"]
