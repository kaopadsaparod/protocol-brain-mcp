"""
Call Graph Explorer for Protocol Brain Context Engine.
Performs bounded upstream (caller) and downstream (callee) graph traversal
using the SQLite relational index without external LLM latency.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .indexer import IncrementalIndexer
from .packer import estimate_tokens
from .storage import IndexStorage


def get_call_graph(
    symbol: str,
    depth: int = 2,
    direction: str = "downstream",
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Traverses the call graph for a given symbol up to a bounded depth.

    Args:
        symbol: The function or method name (e.g. "authenticate" or "login").
        depth: Maximum traversal depth (1 to 5, default: 2).
        direction: "downstream" (callees), "upstream" (callers), or "both".
        workspace_root: Target project directory.
    """
    if not symbol or not symbol.strip():
        return {
            "success": False,
            "error": "Symbol name cannot be empty.",
            "actionable_hint": "Provide a valid function or method name (e.g. 'run_safe_command' or 'prepare_context').",
        }

    clamped_depth = max(1, min(depth, 5))
    norm_direction = direction.lower().strip()
    if norm_direction not in ("downstream", "upstream", "both"):
        norm_direction = "downstream"

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    storage = IndexStorage(root_dir=root)
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    conn = storage.get_connection()
    cur = conn.cursor()

    # Find definition(s) of target symbol
    cur.execute("""
        SELECT s.id, f.path, s.name, s.container, s.type, s.line_start, s.line_end
        FROM symbols s
        JOIN files f ON s.file_id = f.id
        WHERE s.name = ?
        LIMIT 5
    """, (symbol,))
    def_rows = cur.fetchall()

    if not def_rows:
        return {
            "success": True,
            "symbol": symbol,
            "found": False,
            "tree_markdown": f"*(Symbol `{symbol}` not found in indexed workspace)*",
            "nodes": [],
            "edges": [],
        }

    target_def = def_rows[0]
    file_path = target_def["path"]

    def _get_callees(sym_name: str, cur_file: str) -> List[Dict[str, Any]]:
        """Finds what this symbol calls (downstream)."""
        cur.execute("""
            SELECT s.file_id, s.line_start, s.line_end
            FROM symbols s
            JOIN files f ON s.file_id = f.id
            WHERE s.name = ? AND f.path = ?
            LIMIT 1
        """, (sym_name, cur_file))
        row = cur.fetchone()
        if not row:
            # Fallback to just name
            cur.execute("""
                SELECT s.file_id, s.line_start, s.line_end, f.path
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE s.name = ?
                LIMIT 1
            """, (sym_name,))
            row = cur.fetchone()
            if not row:
                return []

        file_id = row[0]
        l_start, l_end = row[1], row[2]

        cur.execute("""
            SELECT DISTINCT sr.target_symbol
            FROM symbol_references sr
            WHERE sr.source_file_id = ? AND sr.line >= ? AND sr.line <= ?
            LIMIT 20
        """, (file_id, l_start, l_end))

        callee_symbols = [r[0] for r in cur.fetchall() if r[0] != sym_name]
        results = []
        for cs in callee_symbols:
            cur.execute("""
                SELECT f.path, s.line_start
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE s.name = ?
                LIMIT 1
            """, (cs,))
            match = cur.fetchone()
            f_p = match[0] if match else "unknown"
            l_num = match[1] if match else 1
            results.append({"name": cs, "file": f_p, "line": l_num})
        return results

    def _get_callers(sym_name: str) -> List[Dict[str, Any]]:
        """Finds who calls this symbol (upstream)."""
        cur.execute("""
            SELECT sr.source_file_id, sr.line, f.path
            FROM symbol_references sr
            JOIN files f ON sr.source_file_id = f.id
            WHERE sr.target_symbol = ?
            LIMIT 20
        """, (sym_name,))
        call_sites = cur.fetchall()

        callers = []
        for sf_id, line, f_path in call_sites:
            cur.execute("""
                SELECT s.name, s.line_start
                FROM symbols s
                WHERE s.file_id = ? AND s.line_start <= ? AND s.line_end >= ?
                ORDER BY (s.line_end - s.line_start) ASC
                LIMIT 1
            """, (sf_id, line, line))
            enclosing = cur.fetchone()
            caller_name = enclosing[0] if enclosing else f"module_scope:{line}"
            callers.append({"name": caller_name, "file": f_path, "line": line})
        return callers

    # Build Tree representation
    nodes: Set[str] = set()
    edges: List[Dict[str, str]] = []
    tree_lines: List[str] = []

    def build_downstream_tree(curr_sym: str, curr_file: str, current_depth: int, prefix: str, visited: Set[str]):
        if current_depth > clamped_depth or curr_sym in visited:
            return
        visited.add(curr_sym)
        nodes.add(curr_sym)

        callees = _get_callees(curr_sym, curr_file)
        for i, callee in enumerate(callees):
            is_last = (i == len(callees) - 1)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            tree_lines.append(f"{prefix}{connector}{callee['name']}() [`{callee['file']}:{callee['line']}`]")
            edges.append({"from": curr_sym, "to": callee["name"], "type": "calls"})

            if callee["name"] not in visited:
                build_downstream_tree(callee["name"], callee["file"], current_depth + 1, prefix + child_prefix, visited.copy())

    def build_upstream_tree(curr_sym: str, current_depth: int, prefix: str, visited: Set[str]):
        if current_depth > clamped_depth or curr_sym in visited:
            return
        visited.add(curr_sym)
        nodes.add(curr_sym)

        callers = _get_callers(curr_sym)
        for i, caller in enumerate(callers):
            is_last = (i == len(callers) - 1)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            tree_lines.append(f"{prefix}{connector}{caller['name']}() [`{caller['file']}:{caller['line']}`]")
            edges.append({"from": caller["name"], "to": curr_sym, "type": "calls"})

            if caller["name"] not in visited:
                build_upstream_tree(caller["name"], current_depth + 1, prefix + child_prefix, visited.copy())

    md_blocks = [f"# 🕸️ Interactive Call Graph: `{symbol}()`", f"- **Location:** `{file_path}:{target_def['line_start']}`", f"- **Direction:** `{norm_direction}` (max depth {clamped_depth})\n"]

    if norm_direction in ("downstream", "both"):
        tree_lines = [f"{symbol}() [`{file_path}:{target_def['line_start']}`]"]
        build_downstream_tree(symbol, file_path, 1, "", set())
        md_blocks.append("### ⬇️ Downstream Flow (Callees)")
        md_blocks.append("```text\n" + "\n".join(tree_lines) + "\n```")

    if norm_direction in ("upstream", "both"):
        tree_lines = [f"{symbol}() [`{file_path}:{target_def['line_start']}`]"]
        build_upstream_tree(symbol, 1, "", set())
        md_blocks.append("### ⬆️ Upstream Flow (Callers)")
        md_blocks.append("```text\n" + "\n".join(tree_lines) + "\n```")

    full_md = "\n".join(md_blocks)
    estimated_tokens = estimate_tokens(full_md)

    return {
        "success": True,
        "symbol": symbol,
        "found": True,
        "direction": norm_direction,
        "depth": clamped_depth,
        "file_path": file_path,
        "line_number": target_def["line_start"],
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "edges": edges,
        "tree_markdown": full_md,
        "estimated_tokens": estimated_tokens,
    }
