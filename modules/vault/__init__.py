"""
Vault integration module for Obsidian Second Brain.
"""
from .app_trigger import open_note_in_obsidian_gui
from .reader import (
    get_backlinks,
    get_vault_index,
    get_vault_path,
    is_safe_vault_path,
    list_all_projects,
    resolve_and_read_note,
)
from .search import search_vault
from .writer import (
    append_project_log,
    append_to_existing_note,
    create_vault_note,
    update_note_frontmatter,
)

__all__ = [
    "get_vault_path",
    "get_vault_index",
    "resolve_and_read_note",
    "list_all_projects",
    "get_backlinks",
    "is_safe_vault_path",
    "search_vault",
    "append_project_log",
    "append_to_existing_note",
    "update_note_frontmatter",
    "create_vault_note",
    "open_note_in_obsidian_gui",
]
