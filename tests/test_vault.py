"""
Tests for Obsidian Vault Integration (Happy path + Failure / Security cases).
"""

from modules.vault.reader import (
    get_backlinks,
    get_vault_index,
    resolve_and_read_note,
)
from modules.vault.writer import (
    create_vault_note,
)


def test_vault_index_success():
    """Happy path: Master index loads correctly."""
    index_text = get_vault_index()
    assert "Obsidian Second Brain" in index_text or "Root Path" in index_text


def test_wikilink_resolver_success():
    """Happy path: Resolves wikilink across directories."""
    res = resolve_and_read_note("[[01_AI_Penetration_Testing]]")
    assert res["success"] is True
    assert "02_Projects" in res["path"]
    assert res["content"] is not None


def test_path_traversal_rejection():
    """Security Failure Case: Path traversal attempts must be blocked."""
    res = resolve_and_read_note("../../Windows/System32/drivers/etc/hosts")
    assert res["success"] is False
    assert "Path traversal" in res["error"]
    assert res["actionable_hint"] is not None


def test_nonexistent_note_failure():
    """Failure Case: Non-existent note should return actionable error."""
    res = resolve_and_read_note("non_existent_note_999999")
    assert res["success"] is False
    assert "not found" in res["error"].lower()
    assert "search_vault_notes" in res["actionable_hint"]


def test_backlinks_discovery():
    """Happy path: Backlink graph finds incoming mentions."""
    res = get_backlinks("00_INDEX")
    assert res["success"] is True
    assert res["total_backlinks"] >= 1


def test_create_note_overwrite_protection(tmp_path):
    """Failure Case: Attempting to create an already existing note should block overwrite."""
    res = create_vault_note("00_INDEX.md", "Overwrite Attempt", "New Content")
    assert res["success"] is False
    assert "already exists" in res["error"].lower()
    assert "append" in res["actionable_hint"].lower()


def test_append_to_hidden_or_non_md_rejected(tmp_path):
    """Appending to .obsidian plugins or non-.md files like conftest.py must be rejected."""
    from unittest.mock import patch

    from modules.vault.writer import append_to_existing_note

    vault = tmp_path / "vault"
    vault.mkdir()
    hidden_dir = vault / ".obsidian" / "plugins" / "x"
    hidden_dir.mkdir(parents=True)
    bad_js = hidden_dir / "main.js"
    bad_js.write_text("console.log(1)", encoding="utf-8")
    conftest = vault / "conftest.py"
    conftest.write_text("# evil test setup", encoding="utf-8")

    with patch("modules.vault.writer.get_vault_path", return_value=vault):
        res_hidden = append_to_existing_note(".obsidian/plugins/x/main.js", "evil payload")
        assert res_hidden["success"] is False
        assert "not found" in res_hidden["error"].lower() or "protected" in res_hidden["error"].lower()

        res_conftest = append_to_existing_note("conftest.py", "import os; os.system('calc')")
        assert res_conftest["success"] is False
        assert "not found" in res_conftest["error"].lower() or "protected" in res_conftest["error"].lower()

