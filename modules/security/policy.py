"""
Security Policy and Capability Management for Protocol Brain.
Defines:
1. Tool Classification (SAFE, MUTATING, DANGEROUS).
2. Fine-grained Capability Permissions (git_read, git_write, run_tests, package_install, system_control).
"""

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..config import get_trusted_workspaces, load_config


def is_path_under_roots(target: Path, roots: List[Path]) -> bool:
    """Verify target path is located within one of the approved root directories."""
    resolved_target = target.resolve()
    for root in roots:
        resolved_root = root.resolve()
        if resolved_root in resolved_target.parents or resolved_target == resolved_root:
            return True
    return False


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
    "prepare_context": ToolCategory.READ_ONLY,
    "inspect_project": ToolCategory.READ_ONLY,
    "trace_error": ToolCategory.READ_ONLY,
    "find_impact": ToolCategory.READ_ONLY,
    "find_relevant_tests": ToolCategory.READ_ONLY,
    "git_context": ToolCategory.READ_ONLY,
    "inspect_runtime": ToolCategory.READ_ONLY,
    "inspect_local_services": ToolCategory.READ_ONLY,
    "get_call_graph": ToolCategory.READ_ONLY,
    "suggest_tests_for_change": ToolCategory.READ_ONLY,
    "find_changed_dependencies": ToolCategory.READ_ONLY,
    "ask_codebase": ToolCategory.READ_ONLY,
    "inspect_docker_stack": ToolCategory.READ_ONLY,
    "why_service_unhealthy": ToolCategory.READ_ONLY,
    "inspect_config_usage": ToolCategory.READ_ONLY,

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

from pathlib import Path

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


def evaluate_tool_capability(tool_name: str) -> tuple[bool, str, str]:
    """
    Evaluates whether an MCP tool is permitted under active security capabilities.
    """
    cfg = load_config()
    capabilities: Dict[str, bool] = cfg.get("capabilities", {
        "git_read": True,
        "git_write": False,
        "run_tests": True,
        "package_install": False,
        "system_control": False,
        "process_termination": False,
    })

    if tool_name == "release_port":
        is_allowed = capabilities.get("process_termination", False)
        if not is_allowed:
            return False, "process_termination", "Tool 'release_port' requires 'process_termination' capability which is disabled by default."
        return True, "process_termination", "Allowed process termination"

    return True, "none", "Tool permitted"


def evaluate_command_capability(argv: List[str], cwd: Optional[Path] = None) -> tuple[bool, str, str]:
    """
    Evaluates whether the given command vector is permitted under the active capability policy.
    Hardens against:
    - Path traversal in python test execution (tests/../evil.py)
    - Git read operations with file write flags (--output) or out-of-bounds reads (--no-index)
    - Git mutating subcommands/flags disguised as read (branch -D, tag -d, remote add)
    - Untrusted npx execution (routed to package_install)
    - Ruff and pytest code injection or source file mutation

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
        "process_termination": False,
    })

    exe_name = argv[0].lower().split(".")[0]
    trusted_workspaces = get_trusted_workspaces(cfg)
    work_dir = cwd.resolve() if cwd else (trusted_workspaces[0] if trusted_workspaces else Path.cwd().resolve())

    # 1. Git command evaluation
    if exe_name == "git":
        # Check path confinement for git global directory flags (-C, --git-dir, --work-tree)
        gi = 1
        while gi < len(argv):
            garg = argv[gi]
            target_path_str: Optional[str] = None
            flag_name: str = ""

            if garg == "-C" and gi + 1 < len(argv):
                flag_name = "-C"
                target_path_str = argv[gi + 1]
                gi += 2
            elif garg.startswith("-C") and len(garg) > 2:
                flag_name = "-C"
                target_path_str = garg[2:]
                gi += 1
            elif garg in ("--git-dir", "--work-tree") and gi + 1 < len(argv):
                flag_name = garg
                target_path_str = argv[gi + 1]
                gi += 2
            elif garg.startswith("--git-dir=") or garg.startswith("--work-tree="):
                flag_name, target_path_str = garg.split("=", 1)
                gi += 1
            else:
                gi += 1

            if target_path_str:
                clean_target = target_path_str.strip("\"'")
                try:
                    resolved_target = (work_dir / clean_target).resolve()
                    if not is_path_under_roots(resolved_target, trusted_workspaces):
                        return False, "system_control", f"Git option '{flag_name}' path '{clean_target}' is outside trusted workspaces."
                except Exception:
                    return False, "system_control", f"Invalid path specified for git option '{flag_name}'."

        # Find git subcommand skipping global flags like -C <path> or --no-pager
        subcmd_idx = 1
        while subcmd_idx < len(argv):
            arg = argv[subcmd_idx]
            if arg in ("-C", "-c", "--git-dir", "--work-tree"):
                subcmd_idx += 2
            elif arg.startswith("-"):
                subcmd_idx += 1
            else:
                break

        if subcmd_idx >= len(argv):
            req_cap = "git_read"
            is_allowed = capabilities.get(req_cap, True)
            return is_allowed, req_cap, "git command without subcommand"

        subcmd = argv[subcmd_idx].lower()
        sub_args = argv[subcmd_idx + 1:]

        # Diff & Log inspection: reject --output or --no-index under git_read
        if subcmd in ("diff", "log"):
            for a in sub_args:
                a_lower = a.lower()
                if a_lower == "-o" or a_lower.startswith("--output"):
                    req_cap = "git_write"
                    is_allowed = capabilities.get(req_cap, False)
                    if not is_allowed:
                        return False, req_cap, f"Git {subcmd} with file output flag '{a}' requires '{req_cap}' capability."
                    return True, req_cap, "Allowed git command with write"
                if a_lower == "--no-index":
                    req_cap = "system_control"
                    is_allowed = capabilities.get(req_cap, False)
                    if not is_allowed:
                        return False, req_cap, f"Git {subcmd} with '--no-index' reads outside repository and requires '{req_cap}'."
                    return True, req_cap, "Allowed git no-index under system_control"
            req_cap = "git_read"

        elif subcmd == "status" or subcmd in ("show", "rev-parse"):
            req_cap = "git_read"

        elif subcmd == "branch":
            # Detect mutating branch operations: delete, rename, copy, create
            mutating_branch_flags = {"-d", "-D", "-m", "-M", "-c", "-C", "--delete", "--move", "--copy", "-u", "--unset-upstream"}
            has_mutating_flag = any(a in mutating_branch_flags for a in sub_args)
            # Creating branch: git branch <branch_name> (non-flag argument present without query flags)
            has_non_flag = any(not a.startswith("-") for a in sub_args)
            has_query_flag = any(a in ("--list", "-l", "-a", "-r", "--show-current", "-v", "--verbose", "--merged", "--no-merged") for a in sub_args)

            if has_mutating_flag or (has_non_flag and not has_query_flag):
                req_cap = "git_write"
            else:
                req_cap = "git_read"

        elif subcmd == "tag":
            mutating_tag_flags = {"-a", "-s", "-u", "-d", "--delete"}
            has_mutating_flag = any(a in mutating_tag_flags for a in sub_args)
            has_non_flag = any(not a.startswith("-") for a in sub_args)
            has_query_flag = any(a in ("-l", "--list", "-n", "--sort", "-v", "--verify") for a in sub_args)

            if has_mutating_flag or (has_non_flag and not has_query_flag):
                req_cap = "git_write"
            else:
                req_cap = "git_read"

        elif subcmd == "remote":
            mutating_remote_verbs = {"add", "rename", "remove", "rm", "set-head", "set-branches", "set-url", "prune"}
            if any(a.lower() in mutating_remote_verbs for a in sub_args):
                req_cap = "git_write"
            else:
                req_cap = "git_read"

        elif subcmd in GIT_WRITE_SUBCOMMANDS:
            req_cap = "git_write"
        else:
            req_cap = "git_write"

        is_allowed = capabilities.get(req_cap, False)
        if not is_allowed:
            return False, req_cap, f"Git subcommand '{subcmd}' requires '{req_cap}' capability which is disabled."
        return True, req_cap, f"Allowed git command under {req_cap}"

    # Helper to check pytest target paths
    def check_pytest_targets(args_to_check: List[str]) -> Optional[tuple[bool, str, str]]:
        for a in args_to_check:
            if a == "-p" or a.startswith("-p=") or a.startswith("--override-ini") or a == "-c" or a.startswith("-c="):
                req = "system_control"
                if not capabilities.get(req, False):
                    return False, req, f"Pytest with custom plugin/config flag '{a}' requires '{req}' capability."
                return True, req, "Allowed pytest with system_control"

        pidx = 0
        while pidx < len(args_to_check):
            parg = args_to_check[pidx]
            if parg in ("-k", "-m", "-o", "--override-ini") and pidx + 1 < len(args_to_check):
                pidx += 2
                continue
            if parg.startswith("--rootdir="):
                root_val = parg.split("=", 1)[1].strip("\"'")
                try:
                    resolved_root = (work_dir / root_val).resolve()
                    if not is_path_under_roots(resolved_root, trusted_workspaces):
                        return False, "system_control", f"Pytest --rootdir path '{root_val}' is outside trusted workspaces."
                except Exception:
                    return False, "system_control", "Invalid path for pytest --rootdir."
            elif parg == "--rootdir" and pidx + 1 < len(args_to_check):
                root_val = args_to_check[pidx + 1].strip("\"'")
                try:
                    resolved_root = (work_dir / root_val).resolve()
                    if not is_path_under_roots(resolved_root, trusted_workspaces):
                        return False, "system_control", f"Pytest --rootdir path '{root_val}' is outside trusted workspaces."
                except Exception:
                    return False, "system_control", "Invalid path for pytest --rootdir."
                pidx += 2
                continue
            elif not parg.startswith("-"):
                raw_target = parg.split("::")[0].strip("\"'")
                if raw_target and (raw_target.endswith(".py") or "/" in raw_target or "\\" in raw_target or (work_dir / raw_target).exists()):
                    try:
                        resolved_target = (work_dir / raw_target).resolve()
                        if not is_path_under_roots(resolved_target, trusted_workspaces):
                            return False, "system_control", f"Pytest target path '{raw_target}' is outside trusted workspaces."
                    except Exception:
                        return False, "system_control", "Invalid target path for pytest."
            pidx += 1
        return None

    # 2. Test runners & Linters (pytest, ruff)
    if exe_name == "pytest":
        target_check = check_pytest_targets(argv[1:])
        if target_check is not None:
            return target_check

        req_cap = "run_tests"
        is_allowed = capabilities.get(req_cap, True)
        if not is_allowed:
            return False, req_cap, f"Command '{exe_name}' requires '{req_cap}' capability which is disabled."
        return True, req_cap, "Allowed test command"

    if exe_name == "ruff":
        # Ruff formatting/fixing modifies files -> requires git_write
        if any(a in ("--fix", "--fix-only") for a in argv[1:]) or (len(argv) >= 2 and argv[1].lower() == "format"):
            req_cap = "git_write"
            is_allowed = capabilities.get(req_cap, False)
            if not is_allowed:
                return False, req_cap, "Ruff file formatting/fixing modifies source code and requires 'git_write' capability."
        else:
            req_cap = "run_tests"
            is_allowed = capabilities.get(req_cap, True)
            if not is_allowed:
                return False, req_cap, f"Command '{exe_name}' requires '{req_cap}' capability which is disabled."

        # Confinement check for target files/directories
        for a in argv[1:]:
            if not a.startswith("-") and a.lower() not in ("check", "format", "clean", "rule", "config"):
                clean_target = a.strip("\"'")
                if clean_target:
                    try:
                        resolved_target = (work_dir / clean_target).resolve()
                        if not is_path_under_roots(resolved_target, trusted_workspaces):
                            return False, "system_control", f"Ruff target path '{clean_target}' is outside trusted workspaces."
                    except Exception:
                        return False, "system_control", "Invalid target path for ruff."

        return True, req_cap, "Allowed ruff command"

    # 3. Python test execution with path traversal defense
    if exe_name == "python":
        if len(argv) >= 3 and argv[1] == "-m":
            module_name = argv[2].lower()
            if module_name in ("pytest", "unittest"):
                target_check = check_pytest_targets(argv[3:])
                if target_check is not None:
                    return target_check

                req_cap = "run_tests"
                is_allowed = capabilities.get(req_cap, True)
                if not is_allowed:
                    return False, req_cap, f"Running tests via python -m {module_name} requires '{req_cap}' capability."
                return True, req_cap, "Allowed python test execution"
            if module_name == "ruff":
                if any(a in ("--fix", "--fix-only") for a in argv[3:]) or (len(argv) >= 4 and argv[3].lower() == "format"):
                    req_cap = "git_write"
                else:
                    req_cap = "run_tests"
                is_allowed = capabilities.get(req_cap, False)
                if not is_allowed:
                    return False, req_cap, f"Running python -m ruff with modification requires '{req_cap}' capability."
                return True, req_cap, "Allowed python ruff execution"

        # Check if running a test script directly
        if len(argv) >= 2:
            target_str = argv[1].strip("\"'")
            tests_dir = (work_dir / "tests").resolve()
            try:
                target_path = (work_dir / target_str).resolve()
                if (tests_dir in target_path.parents or target_path == tests_dir) and target_path.suffix.lower() == ".py":
                    if not is_path_under_roots(target_path, trusted_workspaces):
                        return False, "system_control", f"Python test script '{target_str}' is outside trusted workspaces."
                    req_cap = "run_tests"
                    is_allowed = capabilities.get(req_cap, True)
                    if not is_allowed:
                        return False, req_cap, f"Running tests via python requires '{req_cap}' capability."
                    return True, req_cap, "Allowed python test execution"
            except Exception:
                pass

    # 4. Package managers (npm vs npx)
    if exe_name == "npm":
        if len(argv) >= 2 and argv[1].lower() in ("test", "run", "lint"):
            req_cap = "run_tests"
        else:
            req_cap = "package_install"
        is_allowed = capabilities.get(req_cap, False)
        if not is_allowed:
            return False, req_cap, f"NPM operation '{argv[1] if len(argv) > 1 else ''}' requires '{req_cap}' capability."
        return True, req_cap, "Allowed npm operation"

    if exe_name == "npx":
        # npx downloads/executes arbitrary packages from npm registry -> always requires package_install
        req_cap = "package_install"
        is_allowed = capabilities.get(req_cap, False)
        if not is_allowed:
            return False, req_cap, f"NPX executes arbitrary packages and requires '{req_cap}' capability which is disabled."
        return True, req_cap, "Allowed npx operation"

    # 5. Default fallback to system_control
    req_cap = "system_control"
    is_allowed = capabilities.get(req_cap, False)
    if not is_allowed:
        return False, req_cap, f"Command '{exe_name}' requires '{req_cap}' capability which is disabled by default."
    return True, req_cap, "Allowed under system_control"
