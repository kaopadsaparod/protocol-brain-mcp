"""
Security Policy and Capability Management for Protocol Brain.
Defines:
1. Tool Classification (SAFE, MUTATING, DANGEROUS).
2. Fine-grained Capability Permissions (git_read, git_write, run_tests, package_install, system_control).
"""

from enum import Enum
from typing import Dict, List, Set

from ..config import load_config


class ToolCategory(str, Enum):
    SAFE = "SAFE"            # Read-only, inspection, no side-effects
    MUTATING = "MUTATING"    # Modifies vault notes, generates docs, non-destructive
    DANGEROUS = "DANGEROUS"  # Executes OS processes, terminates ports


TOOL_CATEGORIES: Dict[str, ToolCategory] = {
    # SAFE (Read-Only)
    "read_vault_index": ToolCategory.SAFE,
    "get_note_by_wikilink": ToolCategory.SAFE,
    "search_vault_notes": ToolCategory.SAFE,
    "list_projects": ToolCategory.SAFE,
    "get_note_backlinks": ToolCategory.SAFE,
    "get_file_outline": ToolCategory.SAFE,
    "read_single_symbol": ToolCategory.SAFE,
    "find_code_references": ToolCategory.SAFE,
    "truncate_build_errors": ToolCategory.SAFE,
    "get_active_listening_ports": ToolCategory.SAFE,
    "check_system_and_gpu": ToolCategory.SAFE,
    "check_git_status": ToolCategory.SAFE,
    "get_git_diff": ToolCategory.SAFE,

    # MUTATING (Vault / Documents)
    "append_to_note": ToolCategory.MUTATING,
    "update_frontmatter": ToolCategory.MUTATING,
    "log_project_progress": ToolCategory.MUTATING,
    "create_new_note": ToolCategory.MUTATING,
    "open_note_in_obsidian": ToolCategory.MUTATING,
    "notify_user_windows": ToolCategory.MUTATING,
    "convert_to_thai_pdf": ToolCategory.MUTATING,

    # DANGEROUS (OS & Process Control)
    "run_windows_command": ToolCategory.DANGEROUS,
    "release_port": ToolCategory.DANGEROUS,
}

# Capability mapping for command lines
GIT_READ_SUBCOMMANDS: Set[str] = {
    "status", "diff", "log", "show", "branch", "rev-parse", "tag", "remote"
}
GIT_WRITE_SUBCOMMANDS: Set[str] = {
    "add", "commit", "push", "checkout", "switch", "merge", "rebase", "reset", "stash", "pull"
}


def get_tool_category(tool_name: str) -> ToolCategory:
    """Return the security category for a given tool name."""
    return TOOL_CATEGORIES.get(tool_name, ToolCategory.DANGEROUS)


def evaluate_command_capability(argv: List[str]) -> tuple[bool, str, str]:
    """
    Evaluates whether the given command vector is permitted under the active capability policy.
    Returns: (is_allowed, required_capability, reason_or_error)
    """
    if not argv:
        return False, "none", "Empty argument vector"

    cfg = load_config()
    capabilities: Dict[str, bool] = cfg.get("capabilities", {
        "git_read": True,
        "git_write": False,
        "run_tests": True,
        "package_install": False,
        "system_control": False,
    })

    exe_name = argv[0].lower().split(".")[0]

    # 1. Git subcommands
    if exe_name == "git":
        if len(argv) < 2:
            return capabilities.get("git_read", True), "git_read", "git command without subcommand"
        subcmd = argv[1].lower()
        if subcmd in GIT_READ_SUBCOMMANDS:
            req_cap = "git_read"
        elif subcmd in GIT_WRITE_SUBCOMMANDS:
            req_cap = "git_write"
        else:
            req_cap = "git_write"  # Default unclassified git commands to write

        is_allowed = capabilities.get(req_cap, False)
        if not is_allowed:
            return False, req_cap, f"Git subcommand '{subcmd}' requires '{req_cap}' capability which is disabled."
        return True, req_cap, "Allowed git command"

    # 2. Test runners & linters
    if exe_name in ("pytest", "ruff"):
        req_cap = "run_tests"
        is_allowed = capabilities.get(req_cap, True)
        if not is_allowed:
            return False, req_cap, f"Command '{exe_name}' requires '{req_cap}' capability which is disabled."
        return True, req_cap, "Allowed test/lint command"

    # 3. Python running tests vs general execution
    if exe_name == "python":
        if len(argv) >= 3 and argv[1] == "-m" and argv[2] in ("pytest", "unittest", "ruff"):
            req_cap = "run_tests"
            is_allowed = capabilities.get(req_cap, True)
            if not is_allowed:
                return False, req_cap, f"Running tests via python -m requires '{req_cap}' capability."
            return True, req_cap, "Allowed python test execution"

    # 4. Package managers (npm/npx)
    if exe_name in ("npm", "npx"):
        if len(argv) >= 2 and argv[1].lower() in ("test", "run", "lint"):
            req_cap = "run_tests"
        else:
            req_cap = "package_install"

        is_allowed = capabilities.get(req_cap, False)
        if not is_allowed:
            return False, req_cap, f"NPM operation '{argv[1] if len(argv) > 1 else ''}' requires '{req_cap}' capability."
        return True, req_cap, "Allowed npm operation"

    # 5. Default fallback to system_control
    req_cap = "system_control"
    is_allowed = capabilities.get(req_cap, False)
    if not is_allowed:
        return False, req_cap, f"Command '{exe_name}' requires '{req_cap}' capability which is disabled by default."
    return True, req_cap, "Allowed under system_control"
