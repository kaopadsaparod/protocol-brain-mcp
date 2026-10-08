"""
Protocol Brain - Universal MCP Server
Bridging Obsidian Second Brain, Token-saving Code Intelligence, and Windows OS Power Tools
for AI Agents (agy, Claude Code, Ollama, Terminal AI).

CRITICAL ARCHITECTURE RULES:
1. Never output logs to stdout! Stdout is strictly reserved for the MCP JSON-RPC protocol.
   All logging is routed through 'modules.logger' to stderr and rotating log files.
2. Transport Security: Non-loopback binding requires explicit authentication.
3. Capability-Based Execution: Shell actions are scoped by granular permissions.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from mcp.server.mcpserver import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from modules.code_intel import (
    filter_build_errors,
    find_references,
    get_code_outline,
    read_symbol,
)
from modules.config import load_config
from modules.context_engine import (
    find_impact as _find_impact,
)
from modules.context_engine import (
    find_relevant_tests as _find_relevant_tests,
)
from modules.context_engine import (
    git_context as _git_context,
)
from modules.context_engine import (
    inspect_local_services as _inspect_local_services,
)
from modules.context_engine import (
    inspect_project as _inspect_project,
)
from modules.context_engine import (
    inspect_runtime as _inspect_runtime,
)
from modules.context_engine import (
    prepare_context as _prepare_context,
)
from modules.context_engine import (
    trace_error as _trace_error,
)
from modules.docs import convert_document_to_pdf
from modules.logger import logger
from modules.observability import metrics, observe_tool
from modules.security import (
    TOOL_CATEGORIES,
)
from modules.system import (
    free_port,
    get_git_diff_summary,
    get_git_status,
    get_system_health,
    list_listening_ports,
    run_safe_command,
    send_windows_notification,
)
from modules.vault import (
    append_project_log,
    append_to_existing_note,
    create_vault_note,
    get_backlinks,
    get_vault_index,
    list_all_projects,
    open_note_in_obsidian_gui,
    resolve_and_read_note,
    search_vault,
    update_note_frontmatter,
)

# Initialize MCP Server
app = MCPServer(
    name="protocol-brain",
    version="0.3.0",
    description="Universal Second Brain & Fast Context Engine for Terminal AI Agents",
)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """
    Enforces HTTP Bearer token authentication for HTTP and SSE transports.
    Rejects unauthorized requests with 401 Unauthorized.
    """

    def __init__(self, app, token: str):
        super().__init__(app)
        self.token = token.strip()

    async def dispatch(self, request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer ") or auth_header[7:].strip() != self.token:
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "message": "Missing or invalid Bearer authentication token.",
                },
                status_code=401,
            )
        return await call_next(request)


def create_authenticated_http_app(transport: str, host: str = "127.0.0.1", auth_token: Optional[str] = None):
    """
    Creates and configures the Starlette application with BearerAuthMiddleware if auth_token is set.
    """
    if transport == "sse":
        starlette_app = app.sse_app(host=host)
    elif transport == "streamable-http":
        starlette_app = app.streamable_http_app(host=host)
    else:
        raise ValueError(f"Unsupported HTTP transport: {transport}")

    if auth_token:
        starlette_app.add_middleware(BearerAuthMiddleware, token=auth_token)

    return starlette_app


# ==============================================================================
# 🧠 1. Obsidian Second Brain Tools & Resources (SAFE & MUTATING)
# ==============================================================================

@app.resource("vault://index")
def resource_vault_index() -> str:
    """Master Index (00_INDEX.md) of the Obsidian Second Brain."""
    return get_vault_index()


@app.resource("vault://environment")
def resource_environment() -> str:
    """Development tools, runtimes, and Windows PowerShell quirks."""
    res = resolve_and_read_note("01_System_Environment/02_Dev_Tools_and_Runtimes.md")
    return res.get("content") or "Environment note not found."


@app.resource("system://health")
def resource_system_health() -> str:
    """Current hardware stats snapshot (CPU, RAM, Disks, GPU VRAM)."""
    return json.dumps(get_system_health(), indent=2)


@app.tool()
@observe_tool("read_vault_index")
def read_vault_index() -> str:
    """Read the master 00_INDEX.md file from the Obsidian vault immediately."""
    return get_vault_index()


@app.tool()
@observe_tool("get_note_by_wikilink")
def get_note_by_wikilink(identifier: str) -> Dict[str, Any]:
    """
    Read a note by its Wikilink (e.g. '[[01_AI_Penetration_Testing]]' or note name or relative path).
    Automatically resolves subdirectories within the vault. Guards against path traversal.
    """
    return resolve_and_read_note(identifier)


@app.tool()
@observe_tool("search_vault_notes")
def search_vault_notes(query: str, folder: Optional[str] = None) -> Dict[str, Any]:
    """
    Search inside Markdown notes in the Obsidian Vault.
    Optional folder filter: '01_System_Environment', '02_Projects', '04_CheatSheets'.
    """
    return search_vault(query=query, folder=folder)


@app.tool()
@observe_tool("list_projects")
def list_projects() -> List[Dict[str, str]]:
    """List all project notes stored in the vault's 02_Projects/ folder with titles."""
    return list_all_projects()


@app.tool()
@observe_tool("get_note_backlinks")
def get_note_backlinks(note_identifier: str) -> Dict[str, Any]:
    """
    Find all notes across the vault that link to the specified note (Obsidian Backlink Graph).
    Reveals interconnected architecture and dependencies across projects.
    """
    return get_backlinks(note_identifier)


@app.tool()
@observe_tool("append_to_note")
def append_to_note(note_identifier: str, content: str, heading: Optional[str] = None) -> Dict[str, Any]:
    """
    Append text to an existing note safely without overwriting.
    Optional 'heading' parameter inserts text right under that specific heading.
    """
    return append_to_existing_note(note_identifier, content, heading=heading)


@app.tool()
@observe_tool("update_frontmatter")
def update_frontmatter(note_identifier: str, metadata_updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update or add YAML frontmatter key-values in a note without altering the markdown body.
    """
    return update_note_frontmatter(note_identifier, metadata_updates)


@app.tool()
@observe_tool("log_project_progress")
def log_project_progress(project_identifier: str, summary: str, author: str = "AI Assistant") -> Dict[str, Any]:
    """
    Append a timestamped log entry directly to a project note in 02_Projects/.
    Maintains persistent memory between AI sessions and your Obsidian Second Brain.
    """
    return append_project_log(project_identifier, summary, author=author)


@app.tool()
@observe_tool("create_new_note")
def create_new_note(relative_path: str, title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a new note in the vault with standardized YAML Frontmatter. Blocks accidental overwrite."""
    return create_vault_note(relative_path, title, content, tags=tags)


@app.tool()
@observe_tool("open_note_in_obsidian")
def open_note_in_obsidian(identifier: str) -> Dict[str, Any]:
    """
    Trigger the Obsidian Desktop application on the screen to open the specified note
    via native Obsidian URI (obsidian://open?...).
    """
    return open_note_in_obsidian_gui(identifier)


# ==============================================================================
# 🔍 2. Code Intelligence & Token Savers (SAFE)
# ==============================================================================

@app.tool()
@observe_tool("get_file_outline")
def get_file_outline(file_path: str) -> Dict[str, Any]:
    """
    Extracts high-signal structural outline (classes, methods, functions, line numbers)
    from Python (.py) or JavaScript/TypeScript (.js, .ts, .tsx) without loading the whole file.
    Empirically measured to reduce token consumption by an average of 91.0%
    (ranging from 75.0% to 95.9% across this project's 8 Python modules).
    """
    return get_code_outline(file_path)


@app.tool()
@observe_tool("read_single_symbol")
def read_single_symbol(file_path: str, symbol_name: str) -> Dict[str, Any]:
    """
    Extract ONLY the specific function, method, or class definition from a file.
    Delivers maximum token economy by returning only what is needed.
    Example symbol_name: 'parse_python_outline' or 'MyClass.my_method'.
    """
    return read_symbol(file_path, symbol_name)


@app.tool()
@observe_tool("find_code_references")
def find_code_references(
    query: str,
    root_dir: Optional[str] = None,
    context_lines: int = 2,
) -> Dict[str, Any]:
    """
    Contextual grep across the codebase or vault with preceding/succeeding lines.
    Automatically filters out noisy build and dependency directories (.git, node_modules, .venv).
    """
    return find_references(query=query, root_dir=root_dir, context_lines=context_lines)


@app.tool()
@observe_tool("truncate_build_errors")
def truncate_build_errors(raw_terminal_log: str) -> Dict[str, Any]:
    """
    Filter noisy build, compiler, or test outputs (e.g. npm run build, tsc, pytest),
    extracting only actual failure messages and relevant stack traces.
    """
    return filter_build_errors(raw_terminal_log)


# ==============================================================================
# ⚙️ 3. Windows Guard & Git Power Tools (DANGEROUS & SAFE)
# ==============================================================================

@app.tool()
@observe_tool("release_port")
def release_port(port: int) -> Dict[str, Any]:
    """
    [DANGEROUS] Terminate any process listening on the specified user-space TCP port (1024-65535).
    Guarded by process denylist, ancestor protection, and post-kill verification.
    """
    return free_port(port)


@app.tool()
@observe_tool("get_active_listening_ports")
def get_active_listening_ports() -> List[Dict[str, Any]]:
    """List all listening TCP ports and associated process names on the system."""
    return list_listening_ports()


@app.tool()
@observe_tool("check_system_and_gpu")
def check_system_and_gpu() -> Dict[str, Any]:
    """
    Inspect CPU, RAM, Disk space (C, D, F), and NVIDIA GPU VRAM availability.
    Crucial for Local AI (Ollama) to verify headroom before loading large models.
    """
    return get_system_health()


@app.tool()
@observe_tool("run_windows_command")
def run_windows_command(command: str, cwd: Optional[str] = None, timeout_seconds: int = 60) -> Dict[str, Any]:
    """
    [DANGEROUS] Safely execute a scoped command on Windows.
    Hardened by shell=False, metacharacter defense, CWD boundary checks,
    timeout ceiling, and capability-based policy evaluation.
    """
    return run_safe_command(command, cwd=cwd, timeout_seconds=timeout_seconds)


@app.tool()
@observe_tool("notify_user_windows")
def notify_user_windows(title: str, message: str) -> Dict[str, Any]:
    """
    Send a native Windows Toast notification to alert the user when long-running tasks finish.
    """
    return send_windows_notification(title, message)


@app.tool()
@observe_tool("check_git_status")
def check_git_status(repo_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Get a concise overview of repository status: current branch, staged, unstaged, untracked files.
    """
    return get_git_status(repo_path)


@app.tool()
@observe_tool("get_git_diff")
def get_git_diff(repo_path: Optional[str] = None, staged_only: bool = False) -> Dict[str, Any]:
    """
    Get a token-friendly summary of Git diff changes (file stats + truncated diff preview).
    """
    return get_git_diff_summary(repo_path, staged_only=staged_only)


# ==============================================================================
# 📄 4. Document & Typography Tools (LibreOffice Engine)
# ==============================================================================

@app.tool()
@observe_tool("convert_to_thai_pdf")
def convert_to_thai_pdf(input_file: str, output_directory: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert DOCX or Markdown to high-quality PDF using headless LibreOffice.
    Preserves Thai font rendering and vector sharpness without dropped accents.
    """
    return convert_document_to_pdf(input_file, output_directory=output_directory)


# ==============================================================================
# 🛡️ 5. Security Policy & Observability Inspection Tools (SAFE)
# ==============================================================================

@app.tool()
@observe_tool("get_security_policy")
def get_security_policy() -> Dict[str, Any]:
    """
    Inspect active server capabilities, allowed roots, and tool categories (SAFE, MUTATING, DANGEROUS).
    """
    cfg = load_config()
    return {
        "capabilities": cfg.get("capabilities", {}),
        "allowed_roots": cfg.get("allowed_roots", []),
        "allowed_shell_prefixes": cfg.get("allowed_shell_prefixes", []),
        "tool_categories": {k: v.value for k, v in TOOL_CATEGORIES.items()},
    }


@app.tool()
@observe_tool("get_system_metrics")
def get_system_metrics() -> Dict[str, Any]:
    """
    Inspect live runtime metrics: tool usage count, success rate, average latency, and tokens saved.
    """
    return metrics.get_snapshot()


# ==============================================================================
# 🧠 6. Context Engine & Terminal AI Intelligence Tools (v0.3.0)
# ==============================================================================

@app.tool()
@observe_tool("prepare_context")
def prepare_context(
    query: str,
    budget_tokens: int = 4000,
    max_files: int = 10,
    mode: str = "fast",
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Synthesize minimal, high-signal context packet for Terminal AI under a strict token budget.
    Extracts relevant AST symbol slices with ~90% token reduction vs full files.
    """
    return _prepare_context(
        query=query,
        budget_tokens=budget_tokens,
        max_files=max_files,
        mode=mode,
        workspace_root=workspace_root,
    )


@app.tool()
@observe_tool("inspect_project")
def inspect_project(workspace_root: Optional[str] = None, max_depth: int = 2) -> Dict[str, Any]:
    """
    Generate an immediate architectural blueprint: tech stack, package managers, entry points,
    test runners, and directory map for Terminal AI.
    """
    return _inspect_project(workspace_root=workspace_root, max_depth=max_depth)


@app.tool()
@observe_tool("trace_error")
def trace_error(error_log: str, workspace_root: Optional[str] = None, budget_tokens: int = 3000) -> Dict[str, Any]:
    """
    Diagnose a stack trace or crash log: pinpoints crash site in source code, extracts code slice,
    identifies callers and related tests, and outputs actionable fix suggestions.
    """
    return _trace_error(error_log=error_log, workspace_root=workspace_root, budget_tokens=budget_tokens)


@app.tool()
@observe_tool("find_impact")
def find_impact(symbol_name: str, file_path: Optional[str] = None, workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze blast radius before refactoring: finds all callers, dependent modules, affected tests,
    and assigns a change risk level (LOW/MEDIUM/HIGH/CRITICAL).
    """
    return _find_impact(symbol_name=symbol_name, file_path=file_path, workspace_root=workspace_root)


@app.tool()
@observe_tool("find_relevant_tests")
def find_relevant_tests(target_file_or_symbol: str, workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Locates tests covering a given symbol or file and generates targeted CLI commands to run only those tests.
    """
    return _find_relevant_tests(target_file_or_symbol=target_file_or_symbol, workspace_root=workspace_root)


@app.tool()
@observe_tool("git_context")
def git_context(file_path: Optional[str] = None, commits: int = 5, workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Get token-compact Git history, recent authors/messages, and frequently co-changed files.
    """
    return _git_context(file_path=file_path, commits=commits, workspace_root=workspace_root)


@app.tool()
@observe_tool("inspect_runtime")
def inspect_runtime(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspect development runtime: OS, Python/Node/Git/Docker versions, virtual environments,
    and safe environment variables with 100% secret redaction.
    """
    return _inspect_runtime(workspace_root=workspace_root)


@app.tool()
@observe_tool("inspect_local_services")
def inspect_local_services(workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Discover active listening localhost services (Vite, Next, FastAPI, PostgreSQL, Redis, MCP).
    Identifies process names, PIDs, and ports to prevent conflicts.
    """
    return _inspect_local_services(workspace_root=workspace_root)


# ==============================================================================
# 💬 7. MCP Prompts
# ==============================================================================

@app.prompt()
def bootstrap_session() -> str:
    """Prepares standard system instructions loading Second Brain context and OS rules."""
    index_content = get_vault_index()
    return (
        "You are connected to the user's Obsidian Second Brain and Windows Power Tools.\n"
        "Review the master index below before initiating tasks to save tokens:\n\n"
        f"{index_content}\n"
    )


# ==============================================================================
# 🚀 Entrypoint & Transport Security
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Protocol Brain MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport mode (default: stdio for agy/Claude Code; sse/streamable-http for WebUI/remote)",
    )
    parser.add_argument("--host", type=str, default=None, help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Port for SSE/HTTP transports (default: 8000)")
    parser.add_argument("--vault", type=str, default=None, help="Explicit vault path override")
    parser.add_argument("--auth-token", type=str, default=None, help="Bearer token for HTTP/SSE authentication")
    parser.add_argument(
        "--allow-remote-unauthenticated",
        action="store_true",
        help="Allow binding to non-loopback address without authentication (NOT RECOMMENDED)",
    )

    args = parser.parse_args()

    # Load configuration with CLI overrides
    cli_overrides = {}
    if args.vault:
        cli_overrides["vault_path"] = args.vault
    if args.host:
        cli_overrides["host"] = args.host
    if args.port:
        cli_overrides["port"] = args.port
    if args.auth_token:
        cli_overrides["auth_token"] = args.auth_token

    cfg = load_config(cli_overrides)
    bind_host = cfg.get("host", "127.0.0.1")
    bind_port = cfg.get("port", 8000)
    auth_token = cfg.get("auth_token")

    logger.info(f"Protocol Brain initializing with transport '{args.transport}'")

    if args.transport == "stdio":
        app.run(transport="stdio")
    elif args.transport in ("sse", "streamable-http"):
        # Transport Security Validation
        is_loopback = bind_host in ("127.0.0.1", "localhost", "::1")
        if not is_loopback and not auth_token and not args.allow_remote_unauthenticated:
            err_msg = (
                f"SECURITY REJECTION: Binding to non-loopback host '{bind_host}' without authentication "
                "is strictly blocked. Specify --auth-token, set PROTOCOL_BRAIN_AUTH_TOKEN, "
                "or pass --allow-remote-unauthenticated."
            )
            logger.error(err_msg)
            sys.stderr.write(f"\n{err_msg}\n")
            sys.exit(1)

        import anyio
        import uvicorn

        starlette_app = create_authenticated_http_app(args.transport, host=bind_host, auth_token=auth_token)
        endpoint = "/sse" if args.transport == "sse" else "/mcp"
        logger.info(f"Starting Protocol Brain on {args.transport} at http://{bind_host}:{bind_port}{endpoint}")
        uv_config = uvicorn.Config(starlette_app, host=bind_host, port=bind_port, log_level="info")
        uv_server = uvicorn.Server(uv_config)
        anyio.run(uv_server.serve)


if __name__ == "__main__":
    main()
