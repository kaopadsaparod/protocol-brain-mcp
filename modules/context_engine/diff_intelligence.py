"""
Diff Intelligence & Test Prediction for Protocol Brain Context Engine.
Analyzes git diff hunks to map changed lines to AST symbols, calculates affected dependencies,
and recommends the minimal test subset to run.
"""

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .indexer import IncrementalIndexer
from .storage import IndexStorage


def parse_diff_hunks(diff_text: str) -> Dict[str, List[Tuple[int, int]]]:
    """
    Parses a unified git diff into a mapping of file_path -> list of (start_line, end_line) changed.
    """
    files_changes: Dict[str, List[Tuple[int, int]]] = {}
    current_file = None

    file_header_re = re.compile(r"^diff --git a/(.*?) b/(.*?)$")
    hunk_header_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        fm = file_header_re.match(line)
        if fm:
            current_file = fm.group(2).strip()
            files_changes.setdefault(current_file, [])
            continue

        hm = hunk_header_re.match(line)
        if hm and current_file:
            start_line = int(hm.group(1))
            line_count = int(hm.group(2)) if hm.group(2) else 1
            files_changes[current_file].append((start_line, start_line + max(1, line_count) - 1))

    return files_changes


def get_git_diff_text(workspace_root: Path, staged_only: bool = False) -> str:
    """Retrieves unstaged or staged git diff text."""
    cmd = ["git", "diff"]
    if staged_only:
        cmd.append("--staged")
    try:
        out = subprocess.check_output(cmd, cwd=str(workspace_root), stderr=subprocess.DEVNULL, timeout=4, text=True)
        return out
    except Exception:
        return ""


def suggest_tests_for_change(
    diff: Optional[str] = None,
    staged_only: bool = False,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Predicts and suggests the minimal automated tests to execute based on modified code in git diff.
    """
    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    diff_content = diff if diff is not None else get_git_diff_text(root, staged_only=staged_only)

    if not diff_content or not diff_content.strip():
        return {
            "success": True,
            "has_changes": False,
            "message": "No code changes detected in diff.",
            "changed_symbols": [],
            "recommended_tests": [],
            "recommended_commands": [],
            "summary_markdown": "*(Working tree is clean. No tests needed.)*",
        }

    hunks = parse_diff_hunks(diff_content)
    if not hunks:
        return {
            "success": True,
            "has_changes": False,
            "message": "No modified files recognized in diff.",
            "changed_symbols": [],
            "recommended_tests": [],
            "recommended_commands": [],
        }

    storage = IndexStorage()
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    conn = storage.get_connection()
    cur = conn.cursor()

    changed_symbols: List[Dict[str, Any]] = []
    seen_symbols = set()

    for fpath, ranges in hunks.items():
        norm_path = fpath.replace("\\", "/")
        for l_start, l_end in ranges:
            cur.execute("""
                SELECT s.name, s.type, s.line_start, s.line_end
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE f.path = ? AND (
                    (s.line_start <= ? AND s.line_end >= ?) OR
                    (s.line_start >= ? AND s.line_start <= ?)
                )
            """, (norm_path, l_start, l_start, l_start, l_end))
            for s_name, s_type, sym_l1, sym_l2 in cur.fetchall():
                sym_key = (norm_path, s_name)
                if sym_key not in seen_symbols:
                    seen_symbols.add(sym_key)
                    changed_symbols.append({
                        "file": norm_path,
                        "name": s_name,
                        "type": s_type,
                        "lines": f"{sym_l1}-{sym_l2}",
                    })

    # Find matching tests for changed files and changed symbols
    recommended_tests: List[Dict[str, Any]] = []
    seen_tests = set()

    # 1. Tests covering changed symbols
    for cs in changed_symbols:
        s_name = cs["name"]
        cur.execute("""
            SELECT f.path, t.test_name, t.line
            FROM tests t
            JOIN files f ON t.file_id = f.id
            WHERE t.test_name LIKE ?
        """, (f"%{s_name}%",))
        for tp, tn, tl in cur.fetchall():
            key = (tp, tn)
            if key not in seen_tests:
                seen_tests.add(key)
                recommended_tests.append({"file": tp, "test_name": tn, "line": tl, "reason": f"Directly tests symbol `{s_name}`"})

        cur.execute("""
            SELECT DISTINCT f.path, t.test_name, t.line
            FROM symbol_references sr
            JOIN files f ON sr.source_file_id = f.id
            JOIN tests t ON t.file_id = f.id AND t.line <= sr.line
            WHERE sr.target_symbol = ? AND f.path LIKE '%test%'
        """, (s_name,))
        for tp, tn, tl in cur.fetchall():
            key = (tp, tn)
            if key not in seen_tests:
                seen_tests.add(key)
                recommended_tests.append({"file": tp, "test_name": tn, "line": tl, "reason": f"Calls symbol `{s_name}`"})

    # 2. Test files matching modified file stems
    for fpath in hunks.keys():
        stem = Path(fpath).stem
        cur.execute("""
            SELECT f.path, t.test_name, t.line
            FROM tests t
            JOIN files f ON t.file_id = f.id
            WHERE f.path LIKE ? OR f.path LIKE ?
        """, (f"%test_{stem}.py", f"%{stem}.test.%"))
        for tp, tn, tl in cur.fetchall():
            key = (tp, tn)
            if key not in seen_tests:
                seen_tests.add(key)
                recommended_tests.append({"file": tp, "test_name": tn, "line": tl, "reason": f"Module test suite for `{fpath}`"})

    # Count total tests in workspace for reduction ratio
    cur.execute("SELECT COUNT(*) FROM tests")
    total_tests_in_repo = cur.fetchone()[0] or len(recommended_tests)
    skipped_tests = max(0, total_tests_in_repo - len(recommended_tests))
    savings_pct = round((skipped_tests / max(1, total_tests_in_repo)) * 100, 1)

    # Format recommended CLI commands
    unique_test_files = list(dict.fromkeys(t["file"] for t in recommended_tests))
    recommended_commands: List[str] = []
    for tf in unique_test_files:
        test_names = [t["test_name"] for t in recommended_tests if t["file"] == tf and t["test_name"]]
        if tf.endswith(".py"):
            if test_names and len(test_names) <= 3:
                k_filter = " or ".join(test_names)
                recommended_commands.append(f"pytest {tf} -k \"{k_filter}\"")
            else:
                recommended_commands.append(f"pytest {tf}")
        elif tf.endswith(".ts") or tf.endswith(".js"):
            recommended_commands.append(f"npm test -- {tf}")

    # Build concise markdown summary
    md_lines = [
        f"# 🧪 Diff Test Predictor ({len(hunks)} files modified)",
        f"- **Changed Symbols:** {len(changed_symbols)}",
        f"- **Recommended Tests:** {len(recommended_tests)} / {total_tests_in_repo} total ({savings_pct}% tests skipped)",
        "\n### ⚡ Recommended Test Commands",
    ]
    if recommended_commands:
        for cmd in recommended_commands:
            md_lines.append(f"- `{cmd}`")
    else:
        md_lines.append("- *(No specific tests mapped for this diff)*")

    if changed_symbols:
        md_lines.append("\n### 📍 Modified Symbols Detected")
        for cs in changed_symbols[:8]:
            md_lines.append(f"- `{cs['file']}` → `{cs['name']}` ({cs['type']} L{cs['lines']})")

    return {
        "success": True,
        "has_changes": True,
        "changed_files_count": len(hunks),
        "changed_symbols_count": len(changed_symbols),
        "changed_symbols": changed_symbols,
        "recommended_tests_count": len(recommended_tests),
        "total_workspace_tests": total_tests_in_repo,
        "skipped_tests_count": skipped_tests,
        "test_reduction_percent": savings_pct,
        "recommended_tests": recommended_tests,
        "recommended_commands": recommended_commands,
        "summary_markdown": "\n".join(md_lines),
    }


def find_changed_dependencies(
    diff: Optional[str] = None,
    staged_only: bool = False,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calculates downstream dependency impact and blast radius resulting from a git diff.
    """
    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    diff_content = diff if diff is not None else get_git_diff_text(root, staged_only=staged_only)

    if not diff_content or not diff_content.strip():
        return {
            "success": True,
            "has_changes": False,
            "message": "No code changes detected in diff.",
            "risk_level": "LOW",
            "summary_markdown": "*(Working tree is clean)*",
        }

    hunks = parse_diff_hunks(diff_content)
    storage = IndexStorage()
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    conn = storage.get_connection()
    cur = conn.cursor()

    changed_symbols_set = set()
    for fpath, ranges in hunks.items():
        norm_path = fpath.replace("\\", "/")
        for l_start, l_end in ranges:
            cur.execute("""
                SELECT s.name
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE f.path = ? AND (
                    (s.line_start <= ? AND s.line_end >= ?) OR
                    (s.line_start >= ? AND s.line_start <= ?)
                )
            """, (norm_path, l_start, l_start, l_start, l_end))
            for row in cur.fetchall():
                changed_symbols_set.add(row[0])

    dependent_callers: Dict[str, List[str]] = {}
    total_call_sites = 0

    for s_name in changed_symbols_set:
        cur.execute("""
            SELECT f.path, sr.line
            FROM symbol_references sr
            JOIN files f ON sr.source_file_id = f.id
            WHERE sr.target_symbol = ?
        """, (s_name,))
        rows = cur.fetchall()
        for f_path, line in rows:
            dependent_callers.setdefault(s_name, []).append(f"{f_path}:{line}")
            total_call_sites += 1

    # Dependent modules importing changed files
    dependent_modules: List[str] = []
    for fpath in hunks.keys():
        stem = Path(fpath).stem
        cur.execute("""
            SELECT DISTINCT f.path
            FROM imports i
            JOIN files f ON i.file_id = f.id
            WHERE i.module = ? OR i.module LIKE ?
        """, (stem, f"%.{stem}%"))
        dependent_modules.extend([r[0] for r in cur.fetchall() if r[0] != fpath.replace("\\", "/")])
    dependent_modules = list(dict.fromkeys(dependent_modules))

    # Evaluate blast radius risk
    if total_call_sites == 0 and len(dependent_modules) == 0:
        risk_level = "LOW"
    elif total_call_sites <= 5 and len(dependent_modules) <= 2:
        risk_level = "MEDIUM"
    elif total_call_sites <= 15 or len(dependent_modules) <= 5:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    md_lines = [
        "# 💥 Diff Blast Radius & Dependency Impact",
        f"- **Modified Files:** {len(hunks)}",
        f"- **Modified Symbols:** {len(changed_symbols_set)}",
        f"- **Direct Inbound Usages:** {total_call_sites} call sites across {len(dependent_modules)} modules",
        f"- **Change Risk Assessment:** **{risk_level}**",
    ]

    return {
        "success": True,
        "has_changes": True,
        "risk_level": risk_level,
        "changed_files_count": len(hunks),
        "changed_symbols_count": len(changed_symbols_set),
        "changed_symbols": list(changed_symbols_set),
        "total_call_sites": total_call_sites,
        "dependent_modules": dependent_modules,
        "dependent_callers": dependent_callers,
        "summary_markdown": "\n".join(md_lines),
    }
