"""
Real MCP Protocol Integration Tests.
Spawns the MCP server subprocess via stdio and tests full JSON-RPC protocol round-trip:
initialize -> list_tools -> list_resources -> list_prompts -> call_tool -> verify response.
"""

import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.anyio
async def test_mcp_stdio_protocol_roundtrip():
    """Verifies that the MCP server speaks valid JSON-RPC over stdio and responds to all primitives."""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(PROJECT_ROOT / "server.py"), "--transport", "stdio"],
        cwd=str(PROJECT_ROOT),
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Initialize
            init_result = await session.initialize()
            assert init_result is not None
            assert init_result.server_info.name == "protocol-brain"

            # 2. List Tools
            tools_result = await session.list_tools()
            tool_names = [t.name for t in tools_result.tools]
            assert "read_vault_index" in tool_names
            assert "get_file_outline" in tool_names
            assert "get_security_policy" in tool_names
            assert "run_windows_command" in tool_names
            assert len(tool_names) >= 22

            # 3. List Resources
            resources_result = await session.list_resources()
            resource_uris = [str(r.uri) for r in resources_result.resources]
            assert "vault://index" in resource_uris
            assert "system://health" in resource_uris

            # 4. List Prompts
            prompts_result = await session.list_prompts()
            prompt_names = [p.name for p in prompts_result.prompts]
            assert "bootstrap_session" in prompt_names

            # 5. Call Tool: get_security_policy
            policy_call = await session.call_tool("get_security_policy", {})
            assert policy_call is not None
            assert len(policy_call.content) > 0

            # 6. Call Tool: get_file_outline
            outline_call = await session.call_tool(
                "get_file_outline",
                {"file_path": str(PROJECT_ROOT / "server.py")},
            )
            assert outline_call is not None
            assert len(outline_call.content) > 0
