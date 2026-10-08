"""
Unit tests for Docker Stack & Container Intelligence (inspect_docker_stack, why_service_unhealthy).
Verifies parsing docker-compose.yml, tracking service dependencies, and redacting environment secrets.
"""

from pathlib import Path

import pytest

from modules.context_engine.docker_inspector import inspect_docker_stack, why_service_unhealthy


@pytest.fixture
def docker_workspace(tmp_path: Path):
    """Sets up a mock workspace with a docker-compose.yml file."""
    compose_content = (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        "    ports:\n"
        "      - '3000:80'\n"
        "    depends_on:\n"
        "      - api\n"
        "  api:\n"
        "    build: .\n"
        "    ports:\n"
        "      - '8000:8000'\n"
        "    depends_on:\n"
        "      - postgres\n"
        "    environment:\n"
        "      - DATABASE_URL=postgres://user:secretpass@postgres:5432/db\n"
        "      - PORT=8000\n"
        "  postgres:\n"
        "    image: postgres:15\n"
        "    ports:\n"
        "      - '5432:5432'\n"
    )
    (tmp_path / "docker-compose.yml").write_text(compose_content, encoding="utf-8")
    return tmp_path


def test_inspect_docker_stack(docker_workspace):
    """Verifies parsing compose services, ports, dependencies, and masking secrets."""
    res = inspect_docker_stack(workspace_root=str(docker_workspace))
    assert res["success"] is True
    assert res["has_docker"] is True
    assert res["total_services"] == 3
    assert "web" in res["services"]
    assert "api" in res["services"]
    assert "postgres" in res["services"]
    assert "api" in res["services"]["web"]["depends_on"]

    # Verify secret DATABASE_URL value is NOT leaked in the summary
    serialized = str(res)
    assert "secretpass" not in serialized


def test_inspect_docker_stack_no_docker(tmp_path: Path):
    """Empty workspace without compose files returns has_docker=False cleanly."""
    res = inspect_docker_stack(workspace_root=str(tmp_path))
    assert res["success"] is True
    assert res["has_docker"] is False


def test_why_service_unhealthy():
    """Verifies diagnostic recommendations for service healthcheck."""
    res = why_service_unhealthy("web")
    assert res["success"] is True
    assert len(res["recommendations"]) >= 1
    assert "summary_markdown" in res
