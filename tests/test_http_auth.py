"""
HTTP / SSE Bearer Authentication Middleware Tests for Protocol Brain.
Verifies request-time token validation, rejection of missing/invalid tokens with 401,
and bypass for OPTIONS preflight or unauthenticated loopback setups.
"""

import pytest
from starlette.testclient import TestClient

from server import BearerAuthMiddleware, create_authenticated_http_app


def test_http_auth_rejects_missing_token():
    """Requests to authenticated HTTP endpoints without Authorization header must return 401."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.get("/mcp")
        assert res.status_code == 401
        data = res.json()
        assert data.get("error") == "Unauthorized"
        assert "Missing or invalid Bearer authentication token" in data.get("message", "")


def test_http_auth_rejects_invalid_token():
    """Requests with incorrect Bearer tokens must return 401."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.get("/mcp", headers={"Authorization": "Bearer wrong_token_xyz"})
        assert res.status_code == 401
        data = res.json()
        assert data.get("error") == "Unauthorized"


def test_http_auth_rejects_malformed_header():
    """Requests with malformed Authorization headers (e.g. Basic instead of Bearer) must return 401."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.get("/mcp", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert res.status_code == 401


def test_http_auth_allows_valid_bearer_token():
    """Requests with matching Bearer token must pass authentication middleware."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.get("/mcp", headers={"Authorization": "Bearer test_secret_token_123"})
        # Should not be 401 Unauthorized (400 is MCP protocol level because no streamable params)
        assert res.status_code != 401


def test_http_auth_allows_options_preflight():
    """CORS preflight OPTIONS requests with Origin and Access-Control-Request-Method must bypass Bearer auth check."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.options(
            "/mcp",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert res.status_code != 401


def test_http_auth_rejects_options_without_cors_preflight_headers():
    """OPTIONS requests lacking CORS preflight headers must require authentication and return 401."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token="test_secret_token_123")
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.options("/mcp")
        assert res.status_code == 401
        data = res.json()
        assert "preflight" in data.get("message", "").lower()


def test_http_auth_rejects_empty_token_middleware():
    """Initializing BearerAuthMiddleware with empty/whitespace token must raise ValueError."""
    with pytest.raises(ValueError, match="non-empty, non-whitespace"):
        BearerAuthMiddleware(None, "")

    with pytest.raises(ValueError, match="non-empty, non-whitespace"):
        BearerAuthMiddleware(None, "   ")


def test_http_unauthenticated_mode_allows_requests():
    """When auth_token is None, requests proceed without requiring Authorization header."""
    app = create_authenticated_http_app("streamable-http", host="127.0.0.1", auth_token=None)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        res = client.get("/mcp")
        assert res.status_code != 401
