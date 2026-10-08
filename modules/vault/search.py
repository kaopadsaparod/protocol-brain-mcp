import re
from typing import Any, Dict, Optional

from .reader import get_vault_path


def search_vault(
    query: str,
    folder: Optional[str] = None,
    max_results: int = 10,
    case_sensitive: bool = False
) -> Dict[str, Any]:
    """
    Search inside markdown files in the vault.
    Returns matched filenames, line numbers, and excerpt lines.
    """
    vault = get_vault_path()
    search_root = vault / folder if folder else vault

    if not search_root.exists():
        return {
            "success": False,
            "error": f"Search folder '{folder}' does not exist in vault.",
            "results": [],
        }

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(re.escape(query), flags)
    except Exception as e:
        return {"success": False, "error": f"Invalid query: {e}", "results": []}

    matches = []
    for md_file in search_root.rglob("*.md"):
        if ".obsidian" in md_file.parts:
            continue

        try:
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            file_matches = []
            for idx, line in enumerate(lines, 1):
                if pattern.search(line):
                    file_matches.append({
                        "line": idx,
                        "text": line.strip()[:180],
                    })
                    if len(file_matches) >= 3:
                        break

            if file_matches:
                rel_path = str(md_file.relative_to(vault)).replace("\\", "/")
                matches.append({
                    "file": rel_path,
                    "matched_count": len(file_matches),
                    "snippets": file_matches,
                })

            if len(matches) >= max_results:
                break
        except Exception:
            continue

    return {
        "success": True,
        "query": query,
        "folder": folder or "/",
        "total_files_matched": len(matches),
        "results": matches,
    }
