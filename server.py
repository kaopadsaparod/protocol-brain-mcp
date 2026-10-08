"""
Protocol Brain - Universal MCP Server
Bridging Obsidian Second Brain, Token-saving Code Intelligence, and Windows OS Power Tools
for AI Agents (agy, Claude Code, Ollama, Terminal AI).

CRITICAL ARCHITECTURE RULE:
Never output logs to stdout! Stdout is strictly reserved for the MCP JSON-RPC protocol.
All logging is routed through 'modules.logger' to stderr and rotating log files.
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

from modules.code_intel import (
    filter_build_errors,
    find_references,
    get_code_outline,
    read_symbol,
)
from modules.docs import convert_document_to_pdf
from modules.logger import logger
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
    version="0.2.0",
    description="Universal Second Brain & Windows Power Tools Gateway for AI Agents",
)


# ==============================================================================
# 🧠 1. Obsidian Second Brain Tools & Resources
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
def read_vault_index() -> str:
    """Read the master 00_INDEX.md file from the Obsidian vault immediately."""
    return get_vault_index()


@app.tool()
def get_note_by_wikilink(identifier: str) -> Dict[str, Any]:
    """
    Read a note by its Wikilink (e.g. '[[01_AI_Penetration_Testing]]' or note name or relative path).
    Automatically resolves subdirectories within the vault. Guards against path traversal.
    """
    return resolve_and_read_note(identifier)


@app.tool()
def search_vault_notes(query: str, folder: Optional[str] = None) -> Dict[str, Any]:
    """
    Search inside Markdown notes in the Obsidian Vault.
    Optional folder filter: '01_System_Environment', '02_Projects', '04_CheatSheets'.
    """
    return search_vault(query=query, folder=folder)


@app.tool()
def list_projects() -> List[Dict[str, str]]:
    """List all project notes stored in the vault's 02_Projects/ folder with titles."""
    return list_all_projects()


@app.tool()
def get_note_backlinks(note_identifier: str) -> Dict[str, Any]:
    """
    Find all notes across the vault that link to the specified note (Obsidian Backlink Graph).
    Reveals interconnected architecture and dependencies across projects.
    """
    return get_backlinks(note_identifier)


@app.tool()
def append_to_note(note_identifier: str, content: str, heading: Optional[str] = None) -> Dict[str, Any]:
    """
    Append text to an existing note safely without overwriting.
    Optional 'heading' parameter inserts text right under that specific heading.
    """
    return append_to_existing_note(note_identifier, content, heading=heading)


@app.tool()
def update_frontmatter(note_identifier: str, metadata_updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update or add YAML frontmatter key-values in a note without altering the markdown body.
    """
    return update_note_frontmatter(note_identifier, metadata_updates)


@app.tool()
def log_project_progress(project_identifier: str, summary: str, author: str = "AI Assistant") -> Dict[str, Any]:
    """
    Append a timestamped log entry directly to a project note in 02_Projects/.
    Maintains persistent memory between AI sessions and your Obsidian Second Brain.
    """
    return append_project_log(project_identifier, summary, author=author)


@app.tool()
def create_new_note(relative_path: str, title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a new note in the vault with standardized YAML Frontmatter. Blocks accidental overwrite."""
    return create_vault_note(relative_path, title, content, tags=tags)


@app.tool()
def open_note_in_obsidian(identifier: str) -> Dict[str, Any]:
    """
    Trigger the Obsidian Desktop application on the screen to open the specified note
    via native Obsidian URI (obsidian://open?...).
    """
    return open_note_in_obsidian_gui(identifier)


# ==============================================================================
# 🔍 2. Code Intelligence & Token Optimization Tools (serena / ast-grep style)
# ==============================================================================

@app.tool()
def get_file_outline(file_path: str) -> Dict[str, Any]:
    """
    Extracts high-signal structural outline (classes, methods, functions, line numbers)
    from Python (.py) or JavaScript/TypeScript (.js, .ts, .tsx) without loading the whole file.
    Empirically measured to reduce token consumption by an average of 91.0%
    (ranging from 75.0% to 95.9% across this project's 8 Python modules).
    """
    return get_code_outline(file_path)


@app.tool()
def read_single_symbol(file_path: str, symbol_name: str) -> Dict[str, Any]:
    """
    Extract ONLY the specific function, method, or class definition from a file.
    Delivers maximum token economy by returning only what is needed.
    Example symbol_name: 'parse_python_outline' or 'MyClass.my_method'.
    """
    return read_symbol(file_path, symbol_name)


@app.tool()
def find_code_references(
    query: str,
    root_dir: Optional[str] = None,
    context_lines: int = 2
) -> Dict[str, Any]:
    """
    Contextual grep across the codebase or vault with preceding/succeeding lines.
    Automatically filters out noisy build and dependency directories (.git, node_modules, .venv).
    """
    return find_references(query=query, root_dir=root_dir, context_lines=context_lines)


@app.tool()
def truncate_build_errors(raw_terminal_log: str) -> Dict[str, Any]:
    """
    Filter noisy build, compiler, or test outputs (e.g. npm run build, tsc, pytest),
    extracting only actual failure messages and relevant stack traces.
    """
    return filter_build_errors(raw_terminal_log)


# ==============================================================================
# ⚙️ 3. Windows Guard & Git Power Tools (desktop-commander style)
# ==============================================================================

@app.tool()
def release_port(port: int) -> Dict[str, Any]:
    """
    Terminate any process listening on the specified TCP port (e.g. 3000, 8000, 5173).
    Solves Windows 'EADDRINUSE: address already in use' errors instantly.
    """
    return free_port(port)


@app.tool()
def get_active_listening_ports() -> List[Dict[str, Any]]:
    """List all listening TCP ports and associated process names on the system."""
    return list_listening_ports()


@app.tool()
def check_system_and_gpu() -> Dict[str, Any]:
    """
    Inspect CPU, RAM, Disk space (C, D, F), and NVIDIA GPU VRAM availability.
    Crucial for Local AI (Ollama) to verify headroom before loading large models.
    """
    return get_system_health()


@app.tool()
def run_windows_command(command: str, cwd: Optional[str] = None, timeout_seconds: int = 60) -> Dict[str, Any]:
    """
    Safely execute an allowed shell command on Windows.
    Automatically substitutes 'npm' -> 'npm.cmd' and 'npx' -> 'npx.cmd'
    to prevent PowerShell ExecutionPolicy restrictions, detects local .venv python,
    and enforces strict command prefix allowlist from config.json.
    """
    return run_safe_command(command, cwd=cwd, timeout_seconds=timeout_seconds)


@app.tool()
def notify_user_windows(title: str, message: str) -> Dict[str, Any]:
    """
    Send a native Windows Toast notification to alert the user when long-running tasks finish.
    """
    return send_windows_notification(title, message)


@app.tool()
def check_git_status(repo_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Get a concise overview of repository status: current branch, staged, unstaged, untracked files.
    """
    return get_git_status(repo_path)


@app.tool()
def get_git_diff(repo_path: Optional[str] = None, staged_only: bool = False) -> Dict[str, Any]:
    """
    Get a token-friendly summary of Git diff changes (file stats + truncated diff preview).
    """
    return get_git_diff_summary(repo_path, staged_only=staged_only)


# ==============================================================================
# 📄 4. Document & Typography Tools (LibreOffice Engine)
# ==============================================================================

@app.tool()
def convert_to_thai_pdf(input_file: str, output_directory: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert DOCX or Markdown to high-quality PDF using headless LibreOffice.
    Preserves Thai font rendering and vector sharpness without dropped accents.
    """
    return convert_document_to_pdf(input_file, output_directory=output_directory)


# ==============================================================================
# 💬 5. MCP Prompts
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
# 🚀 Entrypoint
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Protocol Brain MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport mode (default: stdio for agy/Claude Code; sse/streamable-http for WebUI/remote)",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE/HTTP transports (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")

    args = parser.parse_args()

    logger.info(f"Protocol Brain initializing with transport '{args.transport}'")

    if args.transport == "stdio":
        app.run(transport="stdio")
    elif args.transport == "sse":
        logger.info(f"Starting Protocol Brain on SSE at http://{args.host}:{args.port}/sse")
        app.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        logger.info(f"Starting Protocol Brain on Streamable HTTP at http://{args.host}:{args.port}/mcp")
        app.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
