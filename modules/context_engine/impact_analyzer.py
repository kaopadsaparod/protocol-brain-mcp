"""
Impact Analyzer & Git Intelligence for Protocol Brain Context Engine.
Provides blast radius calculation (find_impact), targeted test discovery (find_relevant_tests),
and line-level / commit co-change history (git_context).
Zero-LLM deterministic analysis.
"""

import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger
from .indexer import IncrementalIndexer
from .storage import IndexStorage


def find_impact(
    symbol_name: str,
    file_path: Optional[str] = None,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyzes the blast radius of modifying a symbol or file.
    Finds direct and indirect callers, affected test suites, and assesses change risk.
    """
    if not symbol_name or not symbol_name.strip():
        return {
            "success": False,
            "error": "Symbol name cannot be empty.",
            "actionable_hint": "Provide a symbol name (e.g. 'run_safe_command' or 'IndexStorage').",
        }

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    storage = IndexStorage()
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    conn = storage.get_connection()
    cur = conn.cursor()

    # 1. Find direct symbol references across all files
    cur.execute("""
        SELECT f.path, sr.line
        FROM symbol_references sr
        JOIN files f ON sr.source_file_id = f.id
        WHERE sr.target_symbol = ?
        ORDER BY f.path, sr.line
    """, (symbol_name,))
    reference_rows = cur.fetchall()

    callers_by_file: Dict[str, List[int]] = {}
    for r_file, r_line in reference_rows:
        callers_by_file.setdefault(r_file, []).append(r_line)

    # 2. If file_path is given, also check imports of this module
    dependent_modules: List[str] = []
    if file_path:
        norm_path = file_path.replace("\\", "/")
        stem = Path(norm_path).stem
        cur.execute("""
            SELECT DISTINCT f.path
            FROM imports i
            JOIN files f ON i.file_id = f.id
            WHERE i.module = ? OR i.module LIKE ?
        """, (stem, f"%.{stem}%"))
        dependent_modules = [r[0] for r in cur.fetchall() if r[0] != norm_path]

    # 3. Find affected tests
    affected_tests: List[Dict[str, Any]] = []
    for affected_file in list(callers_by_file.keys()) + dependent_modules:
        if "test" in affected_file.lower():
            cur.execute("""
                SELECT t.test_name, t.line
                FROM tests t
                JOIN files f ON t.file_id = f.id
                WHERE f.path = ?
            """, (affected_file,))
            for t_name, t_line in cur.fetchall():
                affected_tests.append({
                    "test_file": affected_file,
                    "test_name": t_name,
                    "line": t_line,
                })

    # Also search for tests named with symbol
    cur.execute("""
        SELECT f.path, t.test_name, t.line
        FROM tests t
        JOIN files f ON t.file_id = f.id
        WHERE t.test_name LIKE ?
    """, (f"%{symbol_name}%",))
    for f_p, t_n, t_l in cur.fetchall():
        if not any(at["test_file"] == f_p and at["test_name"] == t_n for at in affected_tests):
            affected_tests.append({
                "test_file": f_p,
                "test_name": t_n,
                "line": t_l,
            })

    total_affected_files = len(set(list(callers_by_file.keys()) + dependent_modules))
    total_references = len(reference_rows)

    # Determine risk level
    if total_references == 0 and total_affected_files == 0:
        risk_level = "LOW"
        risk_reasons = ["Zero external references found in the indexed workspace."]
    elif total_affected_files <= 2 and total_references <= 5:
        risk_level = "MEDIUM"
        risk_reasons = [f"Localized impact on {total_affected_files} files with {total_references} call sites."]
    elif total_affected_files <= 5:
        risk_level = "HIGH"
        risk_reasons = [f"Moderate blast radius affecting {total_affected_files} files and {len(affected_tests)} tests."]
    else:
        risk_level = "CRITICAL"
        risk_reasons = [f"High blast radius affecting {total_affected_files} files and {total_references} usages across codebase."]

    if not affected_tests and total_references > 0:
        risk_reasons.append("⚠️ Warning: No automated tests found directly covering this symbol.")

    return {
        "success": True,
        "symbol_name": symbol_name,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "total_references": total_references,
        "total_affected_files": total_affected_files,
        "callers_by_file": callers_by_file,
        "dependent_modules": dependent_modules,
        "affected_tests": affected_tests,
    }


def find_relevant_tests(
    target_file_or_symbol: str,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Locates tests associated with a given symbol or file and returns targeted test execution commands.
    """
    if not target_file_or_symbol or not target_file_or_symbol.strip():
        return {
            "success": False,
            "error": "Target file or symbol name cannot be empty.",
            "actionable_hint": "Specify a file path (e.g. 'modules/security/policy.py') or symbol (e.g. 'run_safe_command').",
        }

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    storage = IndexStorage()
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    conn = storage.get_connection()
    cur = conn.cursor()

    target_clean = target_file_or_symbol.replace("\\", "/").strip()
    is_path = "/" in target_clean or target_clean.endswith(".py") or target_clean.endswith(".ts") or target_clean.endswith(".js")

    matching_tests: List[Dict[str, Any]] = []

    if is_path:
        stem = Path(target_clean).stem
        # Direct test file matching
        cur.execute("""
            SELECT f.path, t.test_name, t.line
            FROM tests t
            JOIN files f ON t.file_id = f.id
            WHERE f.path LIKE ? OR f.path LIKE ?
        """, (f"%test_{stem}.py", f"%{stem}.test.%"))
        for f_path, t_name, l_start in cur.fetchall():
            matching_tests.append({"file": f_path, "test": t_name, "line": l_start})

        # Also search for tests importing or referencing symbols in this file
        cur.execute("""
            SELECT DISTINCT f.path, t.test_name, t.line
            FROM tests t
            JOIN files f ON t.file_id = f.id
            JOIN symbol_references sr ON sr.source_file_id = f.id
            JOIN symbols s ON sr.target_symbol = s.name
            JOIN files target_f ON s.file_id = target_f.id
            WHERE target_f.path = ?
        """, (target_clean,))
        for f_path, t_name, l_start in cur.fetchall():
            if not any(m["file"] == f_path and m["test"] == t_name for m in matching_tests):
                matching_tests.append({"file": f_path, "test": t_name, "line": l_start})
    else:
        # Symbol-based search
        cur.execute("""
            SELECT f.path, t.test_name, t.line
            FROM tests t
            JOIN files f ON t.file_id = f.id
            WHERE t.test_name LIKE ?
        """, (f"%{target_clean}%",))
        for f_path, t_name, l_start in cur.fetchall():
            matching_tests.append({"file": f_path, "test": t_name, "line": l_start})

        # Check references in test files
        cur.execute("""
            SELECT DISTINCT f.path, t.test_name, t.line
            FROM symbol_references sr
            JOIN files f ON sr.source_file_id = f.id
            LEFT JOIN tests t ON t.file_id = f.id AND t.line <= sr.line
            WHERE sr.target_symbol = ? AND f.path LIKE '%test%'
        """, (target_clean,))
        for f_path, t_name, l_start in cur.fetchall():
            t_name_resolved = t_name or "(entire test file)"
            if not any(m["file"] == f_path and m["test"] == t_name_resolved for m in matching_tests):
                matching_tests.append({"file": f_path, "test": t_name_resolved, "line": l_start or 1})

    # Group by test file to construct minimal test commands
    unique_files = list(dict.fromkeys(m["file"] for m in matching_tests))
    recommended_commands: List[str] = []

    for uf in unique_files:
        if uf.endswith(".py"):
            tests_in_file = [m["test"] for m in matching_tests if m["file"] == uf and m["test"] != "(entire test file)"]
            if tests_in_file:
                k_filter = " or ".join(tests_in_file[:3])
                recommended_commands.append(f"pytest {uf} -k \"{k_filter}\"")
            else:
                recommended_commands.append(f"pytest {uf}")
        elif uf.endswith(".ts") or uf.endswith(".js"):
            recommended_commands.append(f"npm test -- {uf}")

    return {
        "success": True,
        "target": target_file_or_symbol,
        "total_tests_found": len(matching_tests),
        "matching_tests": matching_tests,
        "affected_test_files": unique_files,
        "recommended_commands": recommended_commands,
    }


def git_context(
    file_path: Optional[str] = None,
    commits: int = 5,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Retrieves compact commit history, line changes, and co-changed files for AI context.
    """
    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    commits_limit = max(1, min(commits, 20))

    cmd_log = [
        "git", "log",
        f"-n{commits_limit}",
        "--pretty=format:%h|%an|%ar|%s",
    ]
    if file_path:
        cmd_log.extend(["--", file_path])

    try:
        log_out = subprocess.check_output(
            cmd_log,
            cwd=str(root),
            stderr=subprocess.DEVNULL,
            timeout=3,
            text=True,
        )
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute git log: {e}",
            "actionable_hint": "Verify git repository exists and file path is valid.",
        }

    history: List[Dict[str, str]] = []
    for line in log_out.splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) == 4:
            history.append({
                "commit": parts[0],
                "author": parts[1],
                "relative_date": parts[2],
                "message": parts[3],
            })

    # Co-change analysis if file_path is specified
    co_changed_files: List[Dict[str, Any]] = []
    if file_path:
        try:
            # Look at files changed in the commits modifying this file
            co_out = subprocess.check_output(
                ["git", "log", f"-n{max(5, commits_limit * 2)}", "--name-only", "--pretty=format:COMMIT", "--", file_path],
                cwd=str(root),
                stderr=subprocess.DEVNULL,
                timeout=3,
                text=True,
            )
            all_files: List[str] = []
            norm_target = file_path.replace("\\", "/").lower()
            for f in co_out.splitlines():
                f_clean = f.strip().replace("\\", "/")
                if f_clean and f_clean != "COMMIT" and f_clean.lower() != norm_target:
                    all_files.append(f_clean)

            counter = Counter(all_files)
            co_changed_files = [
                {"file": f, "shared_commits": count}
                for f, count in counter.most_common(5)
            ]
        except Exception as e:
            logger.debug(f"Co-change analysis skipped: {e}")

    # Build concise markdown summary
    md_lines = [
        f"### 📜 Git Context: `{file_path or 'Recent Repository Commits'}`",
    ]
    for h in history:
        md_lines.append(f"- **`{h['commit']}`** ({h['relative_date']} by {h['author']}): {h['message']}")

    if co_changed_files:
        md_lines.append("\n**Frequently Co-Changed Files:**")
        for cc in co_changed_files:
            md_lines.append(f"- `{cc['file']}` (in {cc['shared_commits']} commits)")

    return {
        "success": True,
        "file_path": file_path,
        "commits_analyzed": len(history),
        "history": history,
        "co_changed_files": co_changed_files,
        "summary_markdown": "\n".join(md_lines),
    }
