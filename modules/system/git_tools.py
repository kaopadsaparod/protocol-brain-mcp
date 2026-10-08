"""
Lightweight Git inspection tools.
Provides git_status and git_diff_summary without overwhelming the LLM context window.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger

SAFE_GIT_ARGS = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=NUL",
    "--no-pager",
    "--no-optional-locks",
]


def find_git_binary() -> Optional[str]:
    return shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"


def is_git_repo(path: Path) -> bool:
    git_bin = find_git_binary()
    if not git_bin:
        return False
    try:
        res = subprocess.run(
            [git_bin, *SAFE_GIT_ARGS, "rev-parse", "--is-inside-work-tree"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0 and res.stdout.strip() == "true"
    except Exception:
        return False


def get_git_status(repo_path_str: Optional[str] = None) -> Dict[str, Any]:
    """
    Get a concise overview of repository status: current branch, staged, unstaged, untracked files.
    """
    repo = Path(repo_path_str) if repo_path_str else Path.cwd()
    if not repo.exists():
        return {
            "success": False,
            "error": f"Path '{repo}' does not exist.",
            "actionable_hint": "Check the path or pass an existing git repository folder.",
        }

    if not is_git_repo(repo):
        return {
            "success": False,
            "error": f"Directory '{repo}' is not a git repository.",
            "actionable_hint": "Initialize a repository with 'git init' or pass a directory containing a .git folder.",
        }

    git_bin = find_git_binary()
    try:
        # Branch
        b_res = subprocess.run(
            [git_bin, *SAFE_GIT_ARGS, "branch", "--show-current"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )
        current_branch = b_res.stdout.strip() or "HEAD (detached)"

        # Porcelain status
        s_res = subprocess.run(
            [git_bin, *SAFE_GIT_ARGS, "status", "--porcelain=v1"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=5,
        )

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
    repo = Path(repo_path_str) if repo_path_str else Path.cwd()
    if not is_git_repo(repo):
        return {
            "success": False,
            "error": f"'{repo}' is not a git repository.",
            "actionable_hint": "Specify a valid git repository folder.",
        }

    git_bin = find_git_binary()
    try:
        stat_cmd = [git_bin, *SAFE_GIT_ARGS, "diff", "--no-ext-diff", "--no-textconv", "--stat"]
        diff_cmd = [git_bin, *SAFE_GIT_ARGS, "diff", "--no-ext-diff", "--no-textconv"]
        if staged_only:
            stat_cmd.append("--cached")
            diff_cmd.append("--cached")

        # 1. Diff stat
        stat_res = subprocess.run(
            stat_cmd,
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        stat_output = stat_res.stdout.strip()

        # 2. Diff detail (truncated)
        diff_res = subprocess.run(
            diff_cmd,
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        diff_lines = diff_res.stdout.splitlines()

        is_truncated = len(diff_lines) > max_diff_lines
        truncated_diff = "\n".join(diff_lines[:max_diff_lines])

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
