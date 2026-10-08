"""
Unit tests for Context Engine Runtime & Project Inspector.
Verifies secret masking, service discovery, and architecture blueprint synthesis.
"""

from pathlib import Path

from modules.context_engine.project_inspector import inspect_project
from modules.context_engine.runtime_inspector import (
    inspect_local_services,
    inspect_runtime,
    is_sensitive_key,
)


def test_secret_keyword_masking():
    """Confirms sensitive keywords are flagged for secret redaction."""
    assert is_sensitive_key("AWS_SECRET_ACCESS_KEY") is True
    assert is_sensitive_key("GITHUB_TOKEN") is True
    assert is_sensitive_key("DB_PASSWORD") is True
    assert is_sensitive_key("API_KEY") is True
    assert is_sensitive_key("AUTH_HEADER") is True

    assert is_sensitive_key("PATH") is False
    assert is_sensitive_key("VIRTUAL_ENV") is False
    assert is_sensitive_key("PYTHONPATH") is False


def test_inspect_runtime_secret_redaction(monkeypatch):
    """Verifies that secrets in os.environ are never leaked in the runtime snapshot."""
    monkeypatch.setenv("MOCK_SUPER_SECRET_KEY", "sensitive_12345_token")
    monkeypatch.setenv("MOCK_API_KEY", "secret_api_val")

    res = inspect_runtime()
    assert res["success"] is True
    assert res["masked_secrets_count"] >= 2

    # Verify runtime snapshot does NOT include secret keys or values
    serialized = str(res)
    assert "sensitive_12345_token" not in serialized
    assert "secret_api_val" not in serialized


def test_inspect_local_services():
    """Verifies inspect_local_services runs without crash and returns valid structure."""
    res = inspect_local_services()
    assert res["success"] is True
    assert "total_listening_services" in res
    assert "summary_markdown" in res
    assert isinstance(res["services"], list)


def test_inspect_project(tmp_path: Path):
    """Verifies project blueprint generation on a mock Python/FastAPI workspace."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo-app'\ndependencies = ['fastapi>=0.100.0', 'pytest']\n",
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text("print('hello')\n", encoding="utf-8")

    res = inspect_project(workspace_root=str(tmp_path))
    assert res["success"] is True
    assert "Python" in res["tech_stack"]["languages"]
    assert "FastAPI" in res["tech_stack"]["frameworks"]
    assert "server.py" in res["entry_points"]
    assert "blueprint_markdown" in res
    assert "# 🏗️ Project Architecture Blueprint" in res["blueprint_markdown"]
