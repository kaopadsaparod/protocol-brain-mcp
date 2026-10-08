"""
Unit tests for Codebase Reasoning & Q&A Synthesizer (ask_codebase).
Verifies architectural flow synthesis, port question diagnosis, and hard token budget enforcement.
"""

from pathlib import Path

import pytest

from modules.context_engine.codebase_qa import ask_codebase


@pytest.fixture
def qa_workspace(tmp_path: Path):
    """Sets up a mock workspace with an authentication pipeline."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    (app_dir / "auth.py").write_text(
        "class AuthManager:\n"
        "    def authenticate_user(self, username: str) -> bool:\n"
        "        \"\"\"Executes full credential validation flow.\"\"\"\n"
        "        return len(username) > 0\n",
        encoding="utf-8",
    )

    return tmp_path


def test_ask_codebase_flow_synthesis(qa_workspace):
    """Verifies flow tree synthesis for architectural questions."""
    res = ask_codebase(
        question="how does authenticate_user authentication work?",
        budget_tokens=2000,
        workspace_root=str(qa_workspace),
    )
    assert res["success"] is True
    assert res["category"] == "ARCHITECTURAL_FLOW"
    assert "authenticate_user" in res["answer_markdown"]
    assert res["estimated_tokens"] <= 2000


def test_ask_codebase_port_question():
    """Verifies that questions regarding ports trigger port diagnosis."""
    res = ask_codebase(question="ทำไม port 9999 ถึงไม่ทำงาน?")
    assert res["success"] is True
    assert res["category"] == "RUNTIME_PORT"
    assert "Port 9999 Diagnosis" in res["answer_markdown"]


def test_ask_codebase_empty_question():
    """Empty question must return graceful error with actionable hint."""
    res = ask_codebase(question="")
    assert res["success"] is False
    assert "actionable_hint" in res
