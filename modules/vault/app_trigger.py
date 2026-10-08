import os
import urllib.parse
from typing import Any, Dict

from .reader import get_vault_path, resolve_wikilink_path


def open_note_in_obsidian_gui(note_identifier: str) -> Dict[str, Any]:
    """
    Triggers Windows to open the specified note inside the Obsidian Desktop Application
    via Obsidian's native URI scheme (obsidian://open?vault=...&file=...).
    """
    vault = get_vault_path()
    target_file = resolve_wikilink_path(vault, note_identifier)

    if not target_file:
        return {
            "success": False,
            "error": f"Note '{note_identifier}' not found in vault.",
        }

    vault_name = vault.name
    rel_path = str(target_file.relative_to(vault)).replace("\\", "/")
    # Remove .md for obsidian URL
    if rel_path.endswith(".md"):
        rel_path = rel_path[:-3]

    encoded_vault = urllib.parse.quote(vault_name)
    encoded_file = urllib.parse.quote(rel_path)
    obsidian_uri = f"obsidian://open?vault={encoded_vault}&file={encoded_file}"

    try:
        # On Windows, os.startfile opens URLs in default registered handler
        os.startfile(obsidian_uri)
        return {
            "success": True,
            "message": f"Opened '{rel_path}' in Obsidian Desktop",
            "uri": obsidian_uri,
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to trigger Obsidian URI: {e}",
            "uri": obsidian_uri,
        }
