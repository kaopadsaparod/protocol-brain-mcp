"""
Vault reader module for Obsidian Second Brain.
Provides safe, headless access to notes, wikilink resolution, and backlink graphing.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import load_config
from ..logger import logger


def get_vault_path() -> Path:
    """Determine the active Obsidian vault directory with fallback resolution."""
    # 1. Environment variable
    env_path = os.environ.get("OBSIDIAN_VAULT_PATH")
    if env_path and os.path.exists(env_path):
        return Path(env_path).resolve()

    # 2. Config file (with local override support)
    cfg = load_config()
    configured = cfg.get("vault_path")
    if configured and os.path.exists(configured):
        return Path(configured).resolve()

    # 3. Default standard drives (vault preferred, vualt as legacy fallback)
    for candidate in [Path("D:/vault"), Path("D:/vualt"), Path.home() / "Documents" / "Vault"]:
        if candidate.exists():
            return candidate.resolve()

    return Path("D:/vault").resolve()


def is_safe_vault_path(target: Path, vault: Path) -> bool:
    """
    Guards against Path Traversal vulnerabilities and hidden/system directory access.
    Enforces that target resides within vault root and contains no hidden path segments.
    """
    try:
        resolved_target = target.resolve()
        resolved_vault = vault.resolve()
        if not (resolved_vault in resolved_target.parents or resolved_target == resolved_vault):
            return False

        # Reject any path traversing hidden directories (.obsidian, .git, .vscode, etc.)
        rel_parts = resolved_target.relative_to(resolved_vault).parts
        if any(part.startswith(".") for part in rel_parts):
            return False

        # Reject non-markdown files inside vault if target has an extension
        if resolved_target.suffix and resolved_target.suffix.lower() != ".md":
            return False

        return True
    except Exception:
        return False


def resolve_wikilink_path(vault_path: Path, note_identifier: str) -> Optional[Path]:
    """
    Resolve a wikilink like '[[01_AI_Penetration_Testing]]' or relative path
    to a concrete markdown (.md) file path in the vault.
    Strictly enforces .md extension and rejects hidden paths (.obsidian, .git).
    """
    clean_name = note_identifier.strip()
    if clean_name.startswith("[[") and clean_name.endswith("]]"):
        clean_name = clean_name[2:-2]

    # Handle alias like [[Note Name|Display Name]]
    if "|" in clean_name:
        clean_name = clean_name.split("|")[0].strip()

    # Reject attempt to target hidden directory directly
    if any(segment.startswith(".") for segment in Path(clean_name).parts):
        return None

    # Direct relative path check (must end with .md)
    candidate = (vault_path / clean_name).resolve()
    if candidate.suffix.lower() == ".md" and is_safe_vault_path(candidate, vault_path) and candidate.exists() and candidate.is_file():
        return candidate

    if not clean_name.endswith(".md"):
        candidate_md = (vault_path / f"{clean_name}.md").resolve()
        if is_safe_vault_path(candidate_md, vault_path) and candidate_md.exists() and candidate_md.is_file():
            return candidate_md

    # Recursive search by stem/filename
    target_filename = Path(clean_name).name
    if not target_filename.endswith(".md"):
        target_filename += ".md"

    target_lower = target_filename.lower()
    for matched_path in vault_path.rglob("*.md"):
        if is_safe_vault_path(matched_path, vault_path) and matched_path.name.lower() == target_lower:
            return matched_path

    return None


def get_vault_index() -> str:
    """Read the master 00_INDEX.md file from the vault."""
    vault = get_vault_path()
    if not vault.exists():
        return f"Error: Vault directory '{vault}' does not exist. Check config.json."

    index_candidates = [
        vault / "00_INDEX.md",
        vault / "INDEX.md",
        vault / "index.md",
    ]
    for p in index_candidates:
        if p.exists() and is_safe_vault_path(p, vault):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading index file {p}: {e}")
                return f"Error reading index file: {e}"

    available = [f.name for f in vault.glob("*.md")]
    return f"Error: No master index found at {vault}. Available root markdown files: {available}"


def resolve_and_read_note(note_identifier: str) -> Dict[str, Any]:
    """Resolve and read note content safely."""
    vault = get_vault_path()

    # Check for path traversal attempt in input
    if ".." in note_identifier:
        test_path = (vault / note_identifier).resolve()
        if not is_safe_vault_path(test_path, vault):
            return {
                "success": False,
                "error": f"Path traversal rejected: '{note_identifier}' resolves outside the vault root.",
                "actionable_hint": "Specify paths relative to the vault root without parent navigation ('..').",
                "path": None,
                "content": None,
            }

    target_file = resolve_wikilink_path(vault, note_identifier)

    if not target_file:
        return {
            "success": False,
            "error": f"Note '{note_identifier}' not found in vault ({vault}).",
            "actionable_hint": "Use 'search_vault_notes(query)' or 'list_projects()' to discover existing note names.",
            "path": None,
            "content": None,
        }

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        rel_path = str(target_file.relative_to(vault)).replace("\\", "/")
        return {
            "success": True,
            "path": rel_path,
            "full_path": str(target_file),
            "content": content,
        }
    except Exception as e:
        logger.error(f"Error reading note {target_file}: {e}")
        return {
            "success": False,
            "error": f"Failed to read file: {e}",
            "actionable_hint": "Check file permissions and ensure the file is not locked by another process.",
            "path": str(target_file),
            "content": None,
        }


def list_all_projects() -> List[Dict[str, str]]:
    """List all project notes in 02_Projects/ with first heading or summary."""
    vault = get_vault_path()
    projects_dir = vault / "02_Projects"
    if not projects_dir.exists():
        return []

    project_list = []
    for md_file in sorted(projects_dir.glob("*.md")):
        if md_file.name.startswith("00_Projects_Overview"):
            continue
        try:
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                first_lines = [next(f, "") for _ in range(5)]
            title = md_file.stem
            for line in first_lines:
                if line.startswith("# "):
                    title = line[2:].strip()
                    break
            project_list.append({
                "filename": md_file.name,
                "title": title,
                "relative_path": f"02_Projects/{md_file.name}",
            })
        except Exception:
            pass

    return project_list


def get_backlinks(note_identifier: str) -> Dict[str, Any]:
    """
    Find all notes across the vault that link to the specified note (Obsidian Backlinks).
    Searches for [[note_stem]], [[note_filename]], and markdown links [text](note).
    """
    vault = get_vault_path()
    clean_name = note_identifier.strip()
    if clean_name.startswith("[[") and clean_name.endswith("]]"):
        clean_name = clean_name[2:-2]
    if "|" in clean_name:
        clean_name = clean_name.split("|")[0].strip()

    note_stem = Path(clean_name).stem
    link_patterns = [
        re.compile(rf"\[\[{re.escape(note_stem)}(\|[^\]]+)?\]\]", re.IGNORECASE),
        re.compile(rf"\[\[.*?/{re.escape(note_stem)}(\|[^\]]+)?\]\]", re.IGNORECASE),
        re.compile(rf"\[.*?\]\([^\)]*{re.escape(note_stem)}(\.md)?\)", re.IGNORECASE),
    ]

    backlinks = []
    for md_file in vault.rglob("*.md"):
        if ".obsidian" in md_file.parts:
            continue
        # Don't check the note itself
        if md_file.stem.lower() == note_stem.lower():
            continue

        try:
            with open(md_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            matched_lines = []
            for line_no, line in enumerate(lines, 1):
                if any(p.search(line) for p in link_patterns):
                    matched_lines.append({
                        "line": line_no,
                        "snippet": line.strip()[:150],
                    })

            if matched_lines:
                rel_path = str(md_file.relative_to(vault)).replace("\\", "/")
                backlinks.append({
                    "source_note": rel_path,
                    "title": md_file.stem,
                    "mention_count": len(matched_lines),
                    "mentions": matched_lines,
                })
        except Exception as e:
            logger.debug(f"Skipping {md_file} during backlink scan: {e}")

    return {
        "success": True,
        "target_note": note_stem,
        "total_backlinks": len(backlinks),
        "backlinks": backlinks,
    }
