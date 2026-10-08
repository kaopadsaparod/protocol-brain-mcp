"""
Unit tests for Context Engine Core (prepare_context).
Verifies hard token budget limits, deterministic ranking, token savings telemetry, and caching.
"""

from pathlib import Path

import pytest

from modules.context_engine.engine import prepare_context


@pytest.fixture
def mock_code_workspace(tmp_path: Path):
    """Creates a mock workspace with multiple Python modules."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    # auth.py (realistic multi-function service file)
    methods = [
        f"    def auth_method_{i}(self, data: str) -> str:\n"
        f"        \"\"\"Internal authentication helper {i} for crypto validation.\"\"\"\n"
        f"        return f'processed_{i}_{{data}}'\n\n"
        for i in range(25)
    ]
    (app_dir / "auth.py").write_text(
        "import jwt\n\n"
        "class TokenValidator:\n"
        "    def __init__(self, secret: str):\n"
        "        self.secret = secret\n\n"
        "    def validate_token(self, token: str) -> bool:\n"
        "        \"\"\"Validates JWT authorization token signature.\"\"\"\n"
        "        if not token:\n"
        "            return False\n"
        "        return token.startswith('bearer_')\n\n"
        "    def extract_user_id(self, token: str) -> str:\n"
        "        return 'user_123'\n\n"
        + "".join(methods),
        encoding="utf-8",
    )

    # user.py
    (app_dir / "user.py").write_text(
        "from app.auth import TokenValidator\n\n"
        "class UserService:\n"
        "    def __init__(self, validator: TokenValidator):\n"
        "        self.validator = validator\n\n"
        "    def get_user_profile(self, token: str):\n"
        "        if not self.validator.validate_token(token):\n"
        "            raise ValueError('Invalid token')\n"
        "        return {'id': 123, 'name': 'John Doe'}\n",
        encoding="utf-8",
    )

    # Large file to test token budget slicing vs full content
    (app_dir / "large_module.py").write_text(
        "\n".join([f"def helper_func_{i}():\n    return {i}\n" for i in range(50)]),
        encoding="utf-8",
    )

    return tmp_path


def test_prepare_context_token_budget_enforcement(mock_code_workspace):
    """Context engine must strictly respect requested budget_tokens."""
    # Test tight budget (1000 tokens)
    res_1000 = prepare_context(
        query="validate_token JWT authorization",
        budget_tokens=1000,
        workspace_root=str(mock_code_workspace),
    )
    assert res_1000["success"] is True
    assert res_1000["estimated_tokens"] <= 1000
    assert len(res_1000["packed_symbols"]) >= 1
    assert "validate_token" in res_1000["context"]

    # Test larger budget (3000 tokens)
    res_3000 = prepare_context(
        query="validate_token JWT authorization",
        budget_tokens=3000,
        workspace_root=str(mock_code_workspace),
    )
    assert res_3000["success"] is True
    assert res_3000["estimated_tokens"] <= 3000
    assert res_3000["token_savings_percent"] > 0.0


def test_prepare_context_caching(mock_code_workspace):
    """Repeated calls with identical query must return from cache."""
    q = "user profile authorization"
    res1 = prepare_context(query=q, budget_tokens=2000, workspace_root=str(mock_code_workspace))
    assert res1["success"] is True
    assert res1["telemetry"]["cache_hit"] is False

    res2 = prepare_context(query=q, budget_tokens=2000, workspace_root=str(mock_code_workspace))
    assert res2["success"] is True
    assert res2["telemetry"]["cache_hit"] is True


def test_prepare_context_empty_query(mock_code_workspace):
    """Empty query should gracefully fail with actionable hint."""
    res = prepare_context(query="", workspace_root=str(mock_code_workspace))
    assert res["success"] is False
    assert "actionable_hint" in res


def test_prepare_context_invalid_workspace():
    """Invalid workspace root should return error gracefully."""
    res = prepare_context(query="foo", workspace_root="Z:/non_existent_folder_xyz")
    assert res["success"] is False
    assert "Invalid workspace root" in res["error"]
