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
    READ_ONLY = "READ_ONLY"            # Non-mutating inspection of notes, AST, git, system
    USER_VISIBLE = "USER_VISIBLE"      # UI alerts, Obsidian GUI triggers (no data loss)
    DATA_MUTATION = "DATA_MUTATION"    # Edits vault notes, generates docs
    PROCESS_EXECUTION = "PROCESS_EXECUTION"  # Executes scoped OS commands
    PROCESS_TERMINATION = "PROCESS_TERMINATION"  # Terminates listening network processes

    # Backward compatibility aliases
    SAFE = "READ_ONLY"
    MUTATING = "DATA_MUTATION"
    DANGEROUS = "PROCESS_EXECUTION"


TOOL_CATEGORIES: Dict[str, ToolCategory] = {
    # READ_ONLY
    "read_vault_index": ToolCategory.READ_ONLY,
    "get_note_by_wikilink": ToolCategory.READ_ONLY,
    "search_vault_notes": ToolCategory.READ_ONLY,
    "list_projects": ToolCategory.READ_ONLY,
    "get_note_backlinks": ToolCategory.READ_ONLY,
    "get_file_outline": ToolCategory.READ_ONLY,
    "read_single_symbol": ToolCategory.READ_ONLY,
    "find_code_references": ToolCategory.READ_ONLY,
    "truncate_build_errors": ToolCategory.READ_ONLY,
    "get_active_listening_ports": ToolCategory.READ_ONLY,
    "check_system_and_gpu": ToolCategory.READ_ONLY,
    "check_git_status": ToolCategory.READ_ONLY,
    "get_git_diff": ToolCategory.READ_ONLY,
    "get_system_metrics": ToolCategory.READ_ONLY,
    "get_security_policy": ToolCategory.READ_ONLY,

    # USER_VISIBLE
    "notify_user_windows": ToolCategory.USER_VISIBLE,
    "open_note_in_obsidian": ToolCategory.USER_VISIBLE,

    # DATA_MUTATION
    "append_to_note": ToolCategory.DATA_MUTATION,
    "update_frontmatter": ToolCategory.DATA_MUTATION,
    "log_project_progress": ToolCategory.DATA_MUTATION,
    "create_new_note": ToolCategory.DATA_MUTATION,
    "convert_to_thai_pdf": ToolCategory.DATA_MUTATION,

    # PROCESS_EXECUTION
    "run_windows_command": ToolCategory.PROCESS_EXECUTION,

    # PROCESS_TERMINATION
    "release_port": ToolCategory.PROCESS_TERMINATION,
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
    return TOOL_CATEGORIES.get(tool_name, ToolCategory.PROCESS_EXECUTION)


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
        norm_arg1 = argv[1].replace("\\", "/").lower() if len(argv) >= 2 else ""
        if (len(argv) >= 3 and argv[1] == "-m" and argv[2] in ("pytest", "unittest", "ruff")) or (
            norm_arg1.startswith("tests/")
        ):
            req_cap = "run_tests"
            is_allowed = capabilities.get(req_cap, True)
            if not is_allowed:
                return False, req_cap, f"Running tests via python requires '{req_cap}' capability."
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
