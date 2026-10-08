"""
Unit tests for Config & Environment Intelligence (inspect_config_usage).
Verifies tracing variables across .env files, source code usages, and strict secret masking.
"""

from pathlib import Path

import pytest

from modules.context_engine.config_inspector import inspect_config_usage


@pytest.fixture
def config_workspace(tmp_path: Path):
    """Sets up a mock workspace with .env, .env.example, and source code usages."""
    (tmp_path / ".env.example").write_text("DATABASE_URL=postgres://localhost:5432/mydb\nPORT=8000\n", encoding="utf-8")
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://realuser:super_secret_val@localhost:5432/proddb\n", encoding="utf-8")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "db.py").write_text(
        "import os\n\n"
        "db_url = os.environ.get('DATABASE_URL')\n"
        "app_port = os.getenv('PORT', 8000)\n",
        encoding="utf-8",
    )

    return tmp_path


def test_inspect_config_usage_tracing(config_workspace):
    """Verifies finding definitions in .env and usages in src/db.py."""
    res = inspect_config_usage(variable_name="DATABASE_URL", workspace_root=str(config_workspace))
    assert res["success"] is True
    assert res["variable_name"] == "DATABASE_URL"
    assert len(res["defined_in"]) >= 1
    assert any("db.py" in u["file"] for u in res["code_usages"])


def test_inspect_config_usage_secret_redaction(config_workspace, monkeypatch):
    """Verifies sensitive secrets in os.environ are redacted."""
    monkeypatch.setenv("DATABASE_URL", "postgres://user:super_secret_val@localhost/db")
    monkeypatch.setenv("SECRET_KEY", "super_duper_secret_key_123")

    res = inspect_config_usage(variable_name="SECRET_KEY", workspace_root=str(config_workspace))
    assert res["success"] is True
    assert res["is_set"] is True
    assert res["is_secret"] is True
    assert res["masked_value"] == "[REDACTED_SECRET]"

    serialized = str(res)
    assert "super_duper_secret_key_123" not in serialized


def test_inspect_config_usage_empty():
    """Empty variable name returns actionable hint."""
    res = inspect_config_usage(variable_name="")
    assert res["success"] is False
    assert "actionable_hint" in res
