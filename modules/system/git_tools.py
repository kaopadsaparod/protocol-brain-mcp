"""
Lightweight Git inspection tools.
Provides git_status and git_diff_summary without overwhelming the LLM context window.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..logger import logger

SAFE_GIT_ARGS = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=NUL",
    "--no-pager",
    "--no-optional-locks",
]

SAFE_GIT_FLAGS = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=NUL",
    "--no-pager",
    "--no-optional-locks",
    "--no-ext-diff",
    "--no-textconv",
]


def find_git_binary() -> Optional[str]:
    """Resolves and returns the absolute path to a trusted git executable."""
    candidate = shutil.which("git")
    if candidate:
        resolved = Path(candidate).resolve()
        if resolved.is_file():
            return str(resolved)
    for standard_path in [
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
        "/usr/bin/git",
        "/usr/local/bin/git",
    ]:
        p = Path(standard_path)
        if p.exists() and p.is_file():
            return str(p.resolve())
    return None


def run_git(
    args: List[str],
    cwd: Optional[Union[Path, str]] = None,
    timeout: float = 10.0,
    check: bool = False,
    text: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """
    Centrally executes git commands using a trusted absolute binary with hardened security flags:
    -c core.fsmonitor=false -c core.hooksPath=NUL --no-pager --no-optional-locks --no-ext-diff --no-textconv
    """
    git_bin = find_git_binary()
    if not git_bin:
        raise FileNotFoundError("Git executable not found in trusted system paths.")

    cmd = [
        git_bin,
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=NUL",
        "--no-pager",
        "--no-optional-locks",
    ]

    if args:
        subcmd = args[0]
        cmd.append(subcmd)
        sub_args = list(args[1:])
        if subcmd in ("diff", "log", "show"):
            if "--no-ext-diff" not in sub_args:
                sub_args.insert(0, "--no-ext-diff")
            if "--no-textconv" not in sub_args:
                sub_args.insert(1, "--no-textconv")
        cmd.extend(sub_args)
    else:
        cmd.extend(args)

    work_dir = str(cwd) if cwd else None
    res = subprocess.run(
        cmd,
        cwd=work_dir,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
    )
    if check:
        res.check_returncode()
    return res


def is_git_repo(path: Path) -> bool:
    try:
        res = run_git(["rev-parse", "--is-inside-work-tree"], cwd=path, timeout=5.0)
        return res.returncode == 0 and res.stdout.strip() == "true"
    except Exception:
        return False


def get_git_status(repo_path_str: Optional[str] = None) -> Dict[str, Any]:
    """
    Get a concise overview of repository status: current branch, staged, unstaged, untracked files.
    """
    try:
        from ..security.confine import confine
        repo = confine(repo_path_str or Path.cwd(), kind="workspace")
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid or unconfined repository path: {e}",
            "actionable_hint": "Check the path or pass an existing git repository within trusted workspaces.",
        }

    if not is_git_repo(repo):
        return {
            "success": False,
            "error": f"Directory '{repo}' is not a git repository.",
            "actionable_hint": "Initialize a repository with 'git init' or pass a directory containing a .git folder.",
        }

    try:
        # Branch
        b_res = run_git(["branch", "--show-current"], cwd=repo, timeout=5.0)
        current_branch = b_res.stdout.strip() or "HEAD (detached)"

        # Porcelain status
        s_res = run_git(["status", "--porcelain=v1"], cwd=repo, timeout=5.0)

        staged: List[str] = []
        unstaged: List[str] = []
        untracked: List[str] = []

        for line in s_res.stdout.splitlines():
            if len(line) < 3:
                continue
            x = line[0]
            y = line[1]
            file_path = line[3:].strip()

            if x in ["M", "A", "D", "R", "C"]:
                staged.append(f"{x} {file_path}")
            if y in ["M", "D"]:
                unstaged.append(f"{y} {file_path}")
            if x == "?" and y == "?":
                untracked.append(file_path)

        return {
            "success": True,
            "repo_path": str(repo),
            "branch": current_branch,
            "is_clean": len(staged) == 0 and len(unstaged) == 0 and len(untracked) == 0,
            "staged_count": len(staged),
            "unstaged_count": len(unstaged),
            "untracked_count": len(untracked),
            "staged_files": staged,
            "unstaged_files": unstaged,
            "untracked_files": untracked[:20],
        }
    except Exception as e:
        logger.error(f"Error checking git status in {repo}: {e}")
        return {
            "success": False,
            "error": str(e),
            "actionable_hint": "Ensure git is installed and repository is accessible.",
        }


def get_git_diff_summary(
    repo_path_str: Optional[str] = None,
    staged_only: bool = False,
    max_diff_lines: int = 100
) -> Dict[str, Any]:
    """
    Get a token-friendly summary of Git diff changes (file stats + concise truncated diff).
    """
    try:
        from ..security.confine import confine
        repo = confine(repo_path_str or Path.cwd(), kind="workspace")
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid or unconfined repository path: {e}",
            "actionable_hint": "Specify a valid git repository folder within trusted workspaces.",
        }

    if not is_git_repo(repo):
        return {
            "success": False,
            "error": f"'{repo}' is not a git repository.",
            "actionable_hint": "Specify a valid git repository folder.",
        }

    try:
        stat_args = ["diff", "--stat"]
        diff_args = ["diff"]
        if staged_only:
            stat_args.append("--cached")
            diff_args.append("--cached")

        # 1. Diff stat
        stat_res = run_git(stat_args, cwd=repo, timeout=10.0)
        stat_output = stat_res.stdout.strip()

        # 2. Diff detail (truncated)
        diff_res = run_git(diff_args, cwd=repo, timeout=10.0)
        diff_lines = diff_res.stdout.splitlines()

        from ..security.sanitizer import redact_secrets
        is_truncated = len(diff_lines) > max_diff_lines
        truncated_diff = redact_secrets("\n".join(diff_lines[:max_diff_lines]))

        return {
            "success": True,
            "repo_path": str(repo),
            "staged_only": staged_only,
            "stat_summary": stat_output or "No changes detected.",
            "total_diff_lines": len(diff_lines),
            "is_truncated": is_truncated,
            "diff_preview": truncated_diff if diff_lines else "No diff.",
        }
    except Exception as e:
        logger.error(f"Error getting git diff in {repo}: {e}")
        return {"success": False, "error": str(e), "actionable_hint": "Check git repository state."}
