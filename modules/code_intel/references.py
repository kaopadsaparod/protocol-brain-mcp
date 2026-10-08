"""
Contextual Grep and References Finder.
Searches codebases or vaults with surrounding context lines (-C N), skipping binary and cache folders.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv",
    "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".obsidian", "coverage", ".turbo",
}

TEXT_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".yaml", ".yml",
    ".html", ".css", ".scss", ".sql", ".sh", ".ps1", ".cmd", ".bat", ".toml"
}


def find_references(
    query: str,
    root_dir: Optional[str] = None,
    context_lines: int = 2,
    max_matches: int = 15,
    case_sensitive: bool = False
) -> Dict[str, Any]:
    """
    Search for occurrences of a symbol or string across files with preceding and succeeding context lines.
    """
    search_path = Path(root_dir) if root_dir else Path.cwd()
    if not search_path.exists():
        return {
            "success": False,
            "error": f"Search root '{root_dir}' does not exist.",
            "actionable_hint": "Provide a valid absolute or relative directory path.",
            "results": [],
        }

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(re.escape(query), flags)
    except Exception as e:
        return {"success": False, "error": f"Invalid regex pattern: {e}", "actionable_hint": "Check query characters.", "results": []}

    matches: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(search_path):
        # In-place filter out ignored dirs
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

        for file_name in files:
            file_path = Path(root) / file_name
            if file_path.suffix.lower() not in TEXT_EXTENSIONS:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()

                file_hits = []
                for idx, line in enumerate(lines):
                    if pattern.search(line):
                        start_idx = max(0, idx - context_lines)
                        end_idx = min(len(lines), idx + context_lines + 1)
                        context_snippet = [
                            f"{i + 1:4d} | {lines[i].rstrip()}"
                            for i in range(start_idx, end_idx)
                        ]
                        file_hits.append({
                            "match_line": idx + 1,
                            "match_text": line.strip()[:150],
                            "context": "\n".join(context_snippet),
                        })

                        if len(file_hits) >= 3:
                            break

                if file_hits:
                    try:
                        rel = str(file_path.relative_to(search_path)).replace("\\", "/")
                    except ValueError:
                        rel = str(file_path).replace("\\", "/")

                    matches.append({
                        "file": rel,
                        "full_path": str(file_path),
                        "hit_count": len(file_hits),
                        "hits": file_hits,
                    })

                if len(matches) >= max_matches:
                    break
            except Exception as e:
                logger.debug(f"Error reading file {file_path}: {e}")
                continue

        if len(matches) >= max_matches:
            break

    return {
        "success": True,
        "query": query,
        "search_root": str(search_path),
        "total_files_matched": len(matches),
        "results": matches,
    }
