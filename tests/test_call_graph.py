"""
Unit tests for Call Graph Explorer (get_call_graph).
Verifies upstream and downstream traversal, bounded depth, and ASCII tree rendering.
"""

from pathlib import Path

import pytest

from modules.context_engine.call_graph import get_call_graph


@pytest.fixture
def call_graph_workspace(tmp_path: Path):
    """Sets up a mock workspace with a clear caller-callee hierarchy."""
    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()

    # Leaf service
    (auth_dir / "hasher.py").write_text(
        "class PasswordHasher:\n"
        "    def verify_hash(self, raw: str, hashed: str) -> bool:\n"
        "        return raw == hashed\n",
        encoding="utf-8",
    )

    # Intermediate service
    (auth_dir / "service.py").write_text(
        "from auth.hasher import PasswordHasher\n\n"
        "class AuthService:\n"
        "    def __init__(self):\n"
        "        self.hasher = PasswordHasher()\n\n"
        "    def authenticate(self, user: str, password: str) -> bool:\n"
        "        return self.hasher.verify_hash(password, 'mock_hash')\n",
        encoding="utf-8",
    )

    # Controller (Root)
    (auth_dir / "controller.py").write_text(
        "from auth.service import AuthService\n\n"
        "class AuthController:\n"
        "    def __init__(self):\n"
        "        self.auth_svc = AuthService()\n\n"
        "    def login_endpoint(self, username: str, secret: str):\n"
        "        return self.auth_svc.authenticate(username, secret)\n",
        encoding="utf-8",
    )

    return tmp_path


def test_get_call_graph_downstream(call_graph_workspace):
    """Verifies downstream callee traversal from login_endpoint to authenticate."""
    res = get_call_graph(
        symbol="login_endpoint",
        depth=2,
        direction="downstream",
        workspace_root=str(call_graph_workspace),
    )
    assert res["success"] is True
    assert res["found"] is True
    assert res["symbol"] == "login_endpoint"
    assert "authenticate" in res["tree_markdown"]
    assert res["estimated_tokens"] > 0


def test_get_call_graph_upstream(call_graph_workspace):
    """Verifies upstream caller traversal from authenticate to login_endpoint."""
    res = get_call_graph(
        symbol="authenticate",
        depth=2,
        direction="upstream",
        workspace_root=str(call_graph_workspace),
    )
    assert res["success"] is True
    assert res["found"] is True
    assert "login_endpoint" in res["tree_markdown"]


def test_get_call_graph_nonexistent_symbol(call_graph_workspace):
    """Non-existent symbol should return found=False gracefully without error."""
    res = get_call_graph(
        symbol="non_existent_function_xyz",
        workspace_root=str(call_graph_workspace),
    )
    assert res["success"] is True
    assert res["found"] is False


def test_get_call_graph_empty_symbol():
    """Empty symbol input should fail with actionable hint."""
    res = get_call_graph(symbol="")
    assert res["success"] is False
    assert "actionable_hint" in res
