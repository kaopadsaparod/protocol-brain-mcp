"""
Vault writer module for Obsidian Second Brain.
Provides safe appending, YAML Frontmatter updates, and note creation without overwriting.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml

from ..logger import logger
from .reader import get_vault_path, is_safe_vault_path, resolve_wikilink_path


def parse_frontmatter_and_body(content: str) -> tuple[Dict[str, Any], str]:
    """Extract YAML frontmatter and markdown body from note content."""
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            raw_yaml = parts[1]
            body = parts[2]
            try:
                data = yaml.safe_load(raw_yaml) or {}
                return data, body
            except Exception as e:
                logger.warning(f"Failed to parse YAML frontmatter: {e}")
    return {}, content


def append_to_existing_note(
    note_identifier: str,
    content: str,
    heading: Optional[str] = None
) -> Dict[str, Any]:
    """
    Append text to a note safely. If 'heading' is provided (e.g. '## Notes' or 'Notes'),
    it will insert under that heading; otherwise, appends to the end of the note.
    Never overwrites existing content.
    """
    vault = get_vault_path()

    if ".." in note_identifier:
        test_path = (vault / note_identifier).resolve()
        if not is_safe_vault_path(test_path, vault):
            return {
                "success": False,
                "error": "Path traversal detected: target path is outside vault root.",
                "actionable_hint": "Provide a note path within the vault root without '..' navigation.",
            }

    target_file = resolve_wikilink_path(vault, note_identifier)
    if not target_file:
        return {
            "success": False,
            "error": f"Note '{note_identifier}' not found in vault.",
            "actionable_hint": "Use 'create_new_note' if you want to create a brand new note.",
        }

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            original_text = f.read()

        clean_content = content.strip()
        if heading:
            clean_heading = heading.strip().lstrip("#").strip()
            # Search for heading #+ Heading
            import re
            pattern = re.compile(rf"^(#+\s+{re.escape(clean_heading)}\b.*)$", re.MULTILINE | re.IGNORECASE)
            match = pattern.search(original_text)

            if match:
                # Find position right after heading line
                insert_pos = match.end()
                new_text = (
                    original_text[:insert_pos]
                    + f"\n\n{clean_content}\n"
                    + original_text[insert_pos:]
                )
            else:
                # Heading not found, append heading at the bottom
                new_text = original_text.rstrip() + f"\n\n## {clean_heading}\n\n{clean_content}\n"
        else:
            new_text = original_text.rstrip() + f"\n\n{clean_content}\n"

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(new_text)

        rel_path = str(target_file.relative_to(vault)).replace("\\", "/")
        return {
            "success": True,
            "message": f"Successfully appended content to {rel_path}",
            "file": rel_path,
        }
    except Exception as e:
        logger.error(f"Failed to append to {target_file}: {e}")
        return {
            "success": False,
            "error": f"Write failed: {e}",
            "actionable_hint": "Ensure the target file is not open in exclusive write mode by another application.",
        }


def update_note_frontmatter(
    note_identifier: str,
    metadata_updates: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Updates or inserts YAML frontmatter keys without wiping or altering the markdown body.
    """
    vault = get_vault_path()
    target_file = resolve_wikilink_path(vault, note_identifier)

    if not target_file:
        return {
            "success": False,
            "error": f"Note '{note_identifier}' not found.",
            "actionable_hint": "Verify note name with 'search_vault_notes'.",
        }

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        existing_meta, body = parse_frontmatter_and_body(content)
        existing_meta.update(metadata_updates)

        # Rebuild YAML
        yaml_str = yaml.dump(existing_meta, sort_keys=False, allow_unicode=True).strip()
        rebuilt = f"---\n{yaml_str}\n---" + (body if body.startswith("\n") else f"\n\n{body.lstrip()}")

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(rebuilt)

        rel_path = str(target_file.relative_to(vault)).replace("\\", "/")
        return {
            "success": True,
            "message": f"Updated frontmatter in {rel_path}",
            "file": rel_path,
            "updated_keys": list(metadata_updates.keys()),
        }
    except Exception as e:
        logger.error(f"Failed to update frontmatter in {target_file}: {e}")
        return {
            "success": False,
            "error": f"Frontmatter update failed: {e}",
            "actionable_hint": "Check YAML syntax in metadata_updates dictionary.",
        }


def append_project_log(
    project_identifier: str,
    log_content: str,
    author: str = "AI Assistant"
) -> Dict[str, Any]:
    """
    Append an update, log entry, or architectural decision to an existing project note in 02_Projects/.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_formatted = (
        f"### 📝 Log Entry [{timestamp}] by {author}\n"
        f"{log_content.strip()}\n"
    )
    return append_to_existing_note(project_identifier, entry_formatted)


def create_vault_note(
    relative_path: str,
    title: str,
    content: str,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a new note in the vault with standard YAML frontmatter.
    Guards against path traversal and accidental overwrite.
    """
    vault = get_vault_path()

    clean_path = relative_path.replace("\\", "/").strip("/")
    if not clean_path.endswith(".md"):
        clean_path += ".md"

    target_file = (vault / clean_path).resolve()
    if not is_safe_vault_path(target_file, vault):
        return {
            "success": False,
            "error": "Path traversal detected: target path is outside vault root.",
            "actionable_hint": "Specify a relative path within the vault root (e.g. '02_Projects/my_project.md').",
        }

    if target_file.exists():
        return {
            "success": False,
            "error": f"Note '{clean_path}' already exists. Overwrite is blocked.",
            "actionable_hint": "Use 'append_to_existing_note' or 'update_note_frontmatter' to modify an existing note.",
        }

    target_file.parent.mkdir(parents=True, exist_ok=True)

    today = datetime.now().strftime("%Y-%m-%d")
    frontmatter_dict: Dict[str, Any] = {
        "title": title,
        "date": today,
        "tags": tags or ["notes"],
    }
    yaml_str = yaml.dump(frontmatter_dict, sort_keys=False, allow_unicode=True).strip()
    full_text = f"---\n{yaml_str}\n---\n\n# {title}\n\n{content.strip()}\n"

    try:
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(full_text)

        rel = str(target_file.relative_to(vault)).replace("\\", "/")
        return {
            "success": True,
            "message": f"Created new note at {rel}",
            "file": rel,
        }
    except Exception as e:
        logger.error(f"Failed to create note {target_file}: {e}")
        return {"success": False, "error": str(e), "actionable_hint": "Check disk write permissions."}
