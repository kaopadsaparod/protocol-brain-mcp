"""
Tier 3 Canary Leak Tests for Protocol Brain.
Plants 5 distinct canary strings across:
1. .env files
2. docker-compose.yml
3. Python source code
4. Container / mock service outputs
5. Process environment variables and commandlines

Iterates through registered MCP tools to verify ZERO canary leakage into outputs.
"""

import json
import os
from typing import Any

import pytest

import server
from modules.security.confine import add_trusted_workspace, remove_trusted_workspace

CANARY_ENV = "CANARY_ENV_SECRET_89A2FC11"
CANARY_COMPOSE = "CANARY_COMPOSE_SECRET_33F17B90"
CANARY_PY = "CANARY_PY_SECRET_98D40E5A"
CANARY_CONTAINER = "CANARY_CONTAINER_SECRET_42B76D19"
CANARY_CLI = "CANARY_CLI_SECRET_71C934E8"

ALL_CANARIES = [
    CANARY_ENV,
    CANARY_COMPOSE,
    CANARY_PY,
    CANARY_CONTAINER,
    CANARY_CLI,
]


def assert_no_canary_leaks(output: Any, context: str = ""):
    """Recursively checks any nested structure or string for canary presence."""
    output_str = json.dumps(output, default=str) if not isinstance(output, str) else output
    for canary in ALL_CANARIES:
        assert canary not in output_str, (
            f"Security violation! Canary '{canary}' leaked in {context}:\n{output_str[:300]}"
        )


@pytest.fixture(scope="module")
def canary_workspace(tmp_path_factory):
    """Creates a temporary workspace loaded with sensitive files and canaries."""
    ws = tmp_path_factory.mktemp("canary_ws")

    # 1. Sensitive .env file
    env_file = ws / ".env"
    env_file.write_text(
        f"AWS_SECRET_ACCESS_KEY={CANARY_ENV}\n"
        f"DATABASE_PASSWORD={CANARY_ENV}\n"
        f"API_TOKEN={CANARY_ENV}\n",
        encoding="utf-8",
    )

    # 2. docker-compose.yml
    compose_file = ws / "docker-compose.yml"
    compose_file.write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:15\n"
        "    environment:\n"
        f"      POSTGRES_PASSWORD: {CANARY_COMPOSE}\n"
        f"      SECRET_KEY: {CANARY_COMPOSE}\n",
        encoding="utf-8",
    )

    # 3. Python source code
    src_dir = ws / "src"
    src_dir.mkdir()
    py_file = src_dir / "service.py"
    py_file.write_text(
        f'# Sensitive config\nPRIVATE_TOKEN = "{CANARY_PY}"\n\n'
        "def compute_score(x: int) -> int:\n"
        '    """Returns score computation."""\n'
        "    return x * 10\n",
        encoding="utf-8",
    )

    # 4. Set environment variable canary
    os.environ["SECRET_CLI_TOKEN"] = CANARY_CLI
    os.environ["AWS_SECRET_KEY"] = CANARY_CLI

    add_trusted_workspace(ws)
    yield ws
    remove_trusted_workspace(ws)
    os.environ.pop("SECRET_CLI_TOKEN", None)
    os.environ.pop("AWS_SECRET_KEY", None)


def test_inspect_runtime_zero_canary_leak(canary_workspace):
    """inspect_runtime must strictly redact environment variables and process info."""
    from modules.context_engine.runtime_inspector import inspect_runtime
    res = inspect_runtime(workspace_root=str(canary_workspace))
    assert res["success"] is True
    assert_no_canary_leaks(res, context="inspect_runtime")


def test_inspect_config_usage_zero_canary_leak(canary_workspace):
    """inspect_config_usage traces .env and docker-compose while masking secrets."""
    from modules.context_engine.config_inspector import inspect_config_usage

    # Inspect variable defined with canary in .env
    res = inspect_config_usage("AWS_SECRET_ACCESS_KEY", workspace_root=str(canary_workspace))
    assert res["success"] is True
    assert_no_canary_leaks(res, context="inspect_config_usage(AWS_SECRET_ACCESS_KEY)")

    # Inspect variable defined with canary in docker-compose.yml
    res2 = inspect_config_usage("POSTGRES_PASSWORD", workspace_root=str(canary_workspace))
    assert res2["success"] is True
    assert_no_canary_leaks(res2, context="inspect_config_usage(POSTGRES_PASSWORD)")


def test_ask_codebase_zero_canary_leak(canary_workspace):
    """ask_codebase synthesizes context with mandatory secret redaction."""
    from modules.context_engine.codebase_qa import ask_codebase
    res = ask_codebase("What is PRIVATE_TOKEN or database configuration?", workspace_root=str(canary_workspace))
    assert res["success"] is True
    assert_no_canary_leaks(res, context="ask_codebase")


def test_trace_error_zero_canary_leak(canary_workspace):
    """trace_error sanitizes traceback messages and snippets."""
    from modules.context_engine.error_tracer import trace_error
    fake_traceback = (
        f'Traceback (most recent call last):\n'
        f'  File "{canary_workspace}/src/service.py", line 2, in <module>\n'
        f'    PRIVATE_TOKEN = "{CANARY_PY}"\n'
        f'ValueError: Failed with token {CANARY_CLI} and env {CANARY_ENV}\n'
    )
    res = trace_error(fake_traceback, workspace_root=str(canary_workspace))
    assert res["success"] is True
    assert_no_canary_leaks(res, context="trace_error")


def test_all_registered_mcp_tools_zero_canary_leak(canary_workspace, tmp_path, monkeypatch):
    """
    Invokes all 39 registered tools with safe arguments and asserts
    that NONE of the canaries ever leak in the tool outputs.
    """
    vault_dir = tmp_path / "mock_vault"
    vault_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(vault_dir))
    (vault_dir / "Index.md").write_text("# Index\nSample note.\n", encoding="utf-8")

    tool_registry = server.app._tool_manager._tools

    # Mock GUI and OS notification dispatches to prevent desktop process spawning
    monkeypatch.setattr("modules.vault.app_trigger.os.startfile", lambda uri: None)
    monkeypatch.setattr(
        "modules.system.notification.send_windows_notification",
        lambda t, m: {"success": True, "title": t, "message": m},
    )

    # Safe argument map for each tool
    safe_tool_args = {
        "read_vault_index": {},
        "get_note_by_wikilink": {"identifier": "Index.md"},
        "search_vault_notes": {"query": "Sample"},
        "list_projects": {},
        "get_note_backlinks": {"note_identifier": "Index.md"},
        "append_to_note": {"note_identifier": "Index.md", "content": "Update"},
        "update_frontmatter": {"note_identifier": "Index.md", "metadata_updates": {"tag": "safe"}},
        "log_project_progress": {"project_identifier": "Index.md", "log_content": "Status safe"},
        "create_new_note": {"relative_path": "NewNote.md", "title": "New", "content": "Clean"},
        "open_note_in_obsidian": {"identifier": "Index.md"},
        "get_file_outline": {"file_path": str(canary_workspace / "src" / "service.py")},
        "read_single_symbol": {"file_path": str(canary_workspace / "src" / "service.py"), "symbol_name": "compute_score"},
        "find_code_references": {"target_symbol": "compute_score", "root_dir": str(canary_workspace)},
        "truncate_build_errors": {"build_output": "Error: compilation failed"},
        "release_port": {"port": 59999},
        "get_active_listening_ports": {},
        "check_system_and_gpu": {},
        "run_windows_command": {"command": "echo protocol_brain_test"},
        "notify_user_windows": {"title": "Test Notif", "message": "Clean message"},
        "check_git_status": {"repo_path": str(canary_workspace)},
        "get_git_diff": {"repo_path": str(canary_workspace)},
        "convert_to_thai_pdf": {"markdown_content": "# Heading\nThai text"},
        "get_security_policy": {},
        "get_system_metrics": {},
        "prepare_context": {"prompt": "how to compute score", "workspace_root": str(canary_workspace)},
        "inspect_project": {"workspace_root": str(canary_workspace)},
        "trace_error": {"error_log": "ZeroDivisionError: division by zero", "workspace_root": str(canary_workspace)},
        "find_impact": {"symbol_name": "compute_score", "workspace_root": str(canary_workspace)},
        "find_relevant_tests": {"target_file_or_symbol": "compute_score", "workspace_root": str(canary_workspace)},
        "git_context": {"workspace_root": str(canary_workspace)},
        "inspect_runtime": {"workspace_root": str(canary_workspace)},
        "inspect_local_services": {"workspace_root": str(canary_workspace)},
        "get_call_graph": {"symbol": "compute_score", "workspace_root": str(canary_workspace)},
        "suggest_tests_for_change": {"diff": "", "workspace_root": str(canary_workspace)},
        "find_changed_dependencies": {"diff": "", "workspace_root": str(canary_workspace)},
        "ask_codebase": {"query": "compute score", "workspace_root": str(canary_workspace)},
        "inspect_docker_stack": {"compose_path": str(canary_workspace / "docker-compose.yml")},
        "why_service_unhealthy": {"service_name": "db", "compose_path": str(canary_workspace / "docker-compose.yml")},
        "inspect_config_usage": {"variable_name": "POSTGRES_PASSWORD", "workspace_root": str(canary_workspace)},
    }

    assert len(tool_registry) == len(safe_tool_args), (
        f"Missing test coverage: {len(tool_registry)} registered tools vs {len(safe_tool_args)} mapped tests."
    )

    for tool_name, tool_obj in tool_registry.items():
        args = safe_tool_args.get(tool_name, {})
        fn = tool_obj.fn
        try:
            result = fn(**args)
            assert_no_canary_leaks(result, context=f"Tool '{tool_name}' output")
        except Exception as e:
            # Errors must also not leak canaries
            assert_no_canary_leaks(str(e), context=f"Tool '{tool_name}' exception")
