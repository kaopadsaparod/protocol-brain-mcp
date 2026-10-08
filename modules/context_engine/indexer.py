"""
Incremental Codebase Indexer for Protocol Brain Context Engine.
Implements fast mtime/size change detection, targeted AST parsing, and relational indexing.
"""

import ast
import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..logger import logger
from .storage import DatabaseManager, db_manager

# Directories and paths excluded from indexing
IGNORED_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".protocol_brain",
    "coverage",
    ".idea",
    ".vscode",
}

SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
}


def compute_file_hash(content: str) -> str:
    """Compute sha256 hash of file content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


def parse_python_file(content: str, rel_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses Python source using AST to extract symbols, imports, tests, and call references.
    Returns: (symbols, imports, tests, references)
    """
    symbols: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    tests: List[Dict[str, Any]] = []
    references: List[Dict[str, Any]] = []

    try:
        tree = ast.parse(content, filename=rel_path)
    except Exception as e:
        logger.debug(f"AST syntax parse error in {rel_path}: {e}")
        return symbols, imports, tests, references

    is_test_file = "test" in Path(rel_path).name.lower() or "tests/" in rel_path.replace("\\", "/").lower()

    for node in ast.iter_child_nodes(tree):
        # 1. Imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({
                    "module": alias.name,
                    "symbol": None,
                    "alias": alias.asname,
                })
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                imports.append({
                    "module": mod,
                    "symbol": alias.name,
                    "alias": alias.asname,
                })

        # 2. Classes & Functions
        elif isinstance(node, ast.ClassDef):
            c_doc = ast.get_docstring(node)
            symbols.append({
                "name": node.name,
                "container": None,
                "type": "class",
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno),
                "signature": f"class {node.name}",
                "docstring": c_doc[:200] if c_doc else None,
            })
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_type = "async_method" if isinstance(child, ast.AsyncFunctionDef) else "method"
                    fn_args = [arg.arg for arg in child.args.args]
                    sig = f"def {child.name}({', '.join(fn_args)})"
                    doc = ast.get_docstring(child)
                    symbols.append({
                        "name": child.name,
                        "container": node.name,
                        "type": fn_type,
                        "line_start": child.lineno,
                        "line_end": getattr(child, "end_lineno", child.lineno),
                        "signature": sig,
                        "docstring": doc[:200] if doc else None,
                    })
                    if is_test_file and child.name.startswith("test"):
                        tests.append({
                            "test_name": f"{node.name}.{child.name}",
                            "target_symbol": child.name.replace("test_", ""),
                            "line": child.lineno,
                        })

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_type = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
            fn_args = [arg.arg for arg in node.args.args]
            sig = f"def {node.name}({', '.join(fn_args)})"
            doc = ast.get_docstring(node)
            symbols.append({
                "name": node.name,
                "container": None,
                "type": fn_type,
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno),
                "signature": sig,
                "docstring": doc[:200] if doc else None,
            })
            if is_test_file and node.name.startswith("test"):
                tests.append({
                    "test_name": node.name,
                    "target_symbol": node.name.replace("test_", ""),
                    "line": node.lineno,
                })

    # Walk calls for symbol references
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = None
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            if call_name and not call_name.startswith("__"):
                references.append({
                    "target_symbol": call_name,
                    "line": getattr(node, "lineno", 1),
                })

    return symbols, imports, tests, references


def parse_js_ts_file(content: str, rel_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Pattern-based extractor for JavaScript / TypeScript files."""
    symbols: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    tests: List[Dict[str, Any]] = []
    references: List[Dict[str, Any]] = []

    lines = content.splitlines()
    is_test_file = any(t in rel_path.lower() for t in (".test.", ".spec.", "/tests/", "/test/"))

    symbol_patterns = [
        (re.compile(r"^\s*(export\s+)?class\s+([A-Za-z0-9_$]+)"), "class"),
        (re.compile(r"^\s*(export\s+)?interface\s+([A-Za-z0-9_$]+)"), "interface"),
        (re.compile(r"^\s*(export\s+)?type\s+([A-Za-z0-9_$]+)\s*="), "type"),
        (re.compile(r"^\s*(export\s+)?(async\s+)?function\s+([A-Za-z0-9_$]+)"), "function"),
        (re.compile(r"^\s*(export\s+)?(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s*)?\("), "arrow_function"),
    ]
    import_pattern = re.compile(r"^\s*import\s+(?:\{([^}]+)\}|\*\s+as\s+([A-Za-z0-9_$]+)|([A-Za-z0-9_$]+))\s+from\s+['\"]([^'\"]+)['\"]")
    test_pattern = re.compile(r"^\s*(test|it)\s*\(\s*['\"]([^'\"]+)['\"]")

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Check imports
        m_imp = import_pattern.search(line)
        if m_imp:
            named_group, star_group, default_group, module_path = m_imp.groups()
            if named_group:
                for sym in named_group.split(","):
                    sym_clean = sym.strip().split(" as ")[0].strip()
                    if sym_clean:
                        imports.append({"module": module_path, "symbol": sym_clean, "alias": None})
            elif star_group:
                imports.append({"module": module_path, "symbol": "*", "alias": star_group})
            elif default_group:
                imports.append({"module": module_path, "symbol": "default", "alias": default_group})
            continue

        # Check tests
        if is_test_file:
            m_test = test_pattern.search(line)
            if m_test:
                tests.append({
                    "test_name": m_test.group(2),
                    "target_symbol": m_test.group(2).split()[0],
                    "line": idx,
                })

        # Check symbols
        for pat, sym_type in symbol_patterns:
            m_sym = pat.search(line)
            if m_sym:
                groups = [g for g in m_sym.groups() if g and g not in ("export", "async", "const", "let", "var")]
                sym_name = groups[-1] if groups else m_sym.group(0).strip()
                symbols.append({
                    "name": sym_name,
                    "container": None,
                    "type": sym_type,
                    "line_start": idx,
                    "line_end": idx,
                    "signature": stripped[:120],
                    "docstring": None,
                })
                break

    return symbols, imports, tests, references


class CodebaseIndexer:
    """Manages incremental indexing of project workspaces."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        workspace_root: Optional[Path] = None,
        storage: Optional[DatabaseManager] = None,
    ):
        self.db = storage or db or db_manager
        self.workspace_root = (workspace_root or Path.cwd()).resolve()

    def index_workspace(
        self,
        root_dir: Optional[Path] = None,
        max_depth: Optional[int] = None,
        force_reindex: bool = False,
    ) -> Dict[str, Any]:
        """
        Incrementally indexes the workspace directory.
        Uses mtime/size checks for sub-millisecond cache hits on unchanged files.
        """
        start_time = time.perf_counter()
        workspace_root = (root_dir or self.workspace_root or Path.cwd()).resolve()

        self.db.init_schema()

        # Gather existing records in SQLite
        existing_records: Dict[str, Tuple[int, float, int]] = {}
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            for row in cur.execute("SELECT id, path, mtime, size FROM files"):
                existing_records[row["path"]] = (row["id"], row["mtime"], row["size"])

        scanned_paths: Set[str] = set()
        files_scanned = 0
        files_indexed = 0
        cache_hits = 0

        # Scan filesystem
        with self.db.get_connection() as conn:
            cur = conn.cursor()

            for root, dirs, filenames in os.walk(workspace_root):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]

                for fn in filenames:
                    ext = Path(fn).suffix.lower()
                    if ext not in SUPPORTED_EXTENSIONS:
                        continue

                    full_path = Path(root) / fn
                    try:
                        st = full_path.stat()
                    except (OSError, FileNotFoundError):
                        continue

                    files_scanned += 1
                    try:
                        rel_path = str(full_path.relative_to(workspace_root)).replace("\\", "/")
                    except ValueError:
                        rel_path = str(full_path).replace("\\", "/")

                    scanned_paths.add(rel_path)

                    # Fast-path check: mtime and size match
                    if not force_reindex and rel_path in existing_records:
                        _file_id, db_mtime, db_size = existing_records[rel_path]
                        if abs(st.st_mtime - db_mtime) < 0.001 and st.st_size == db_size:
                            cache_hits += 1
                            continue

                    # Read and parse file
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except Exception as e:
                        logger.debug(f"Failed to read file {rel_path}: {e}")
                        continue

                    content_hash = compute_file_hash(content)
                    total_lines = content.count("\n") + 1
                    lang = SUPPORTED_EXTENSIONS[ext]

                    if lang == "python":
                        symbols, imports, tests, references = parse_python_file(content, rel_path)
                    else:
                        symbols, imports, tests, references = parse_js_ts_file(content, rel_path)

                    # Update database in transaction
                    cur.execute("DELETE FROM files WHERE path = ?", (rel_path,))
                    cur.execute(
                        "INSERT INTO files (path, mtime, size, hash, lang, total_lines) VALUES (?, ?, ?, ?, ?, ?)",
                        (rel_path, st.st_mtime, st.st_size, content_hash, lang, total_lines),
                    )
                    file_id = cur.lastrowid

                    for s in symbols:
                        cur.execute(
                            "INSERT INTO symbols (file_id, name, container, type, line_start, line_end, signature, docstring) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (file_id, s["name"], s.get("container"), s["type"], s["line_start"], s["line_end"], s.get("signature"), s.get("docstring")),
                        )

                    for imp in imports:
                        cur.execute(
                            "INSERT INTO imports (file_id, module, symbol, alias) VALUES (?, ?, ?, ?)",
                            (file_id, imp["module"], imp.get("symbol"), imp.get("alias")),
                        )

                    for t in tests:
                        cur.execute(
                            "INSERT INTO tests (file_id, test_name, target_symbol, line) VALUES (?, ?, ?, ?)",
                            (file_id, t["test_name"], t.get("target_symbol"), t["line"]),
                        )

                    for r in references:
                        cur.execute(
                            "INSERT INTO symbol_references (source_file_id, target_symbol, line) VALUES (?, ?, ?)",
                            (file_id, r["target_symbol"], r["line"]),
                        )

                    files_indexed += 1

            # Prune files deleted from disk
            deleted_paths = set(existing_records.keys()) - scanned_paths
            for del_path in deleted_paths:
                cur.execute("DELETE FROM files WHERE path = ?", (del_path,))

            conn.commit()

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(f"Indexed workspace: {files_indexed} changed, {cache_hits} hits, {len(deleted_paths)} pruned in {elapsed_ms}ms")

        return {
            "success": True,
            "workspace": str(workspace_root),
            "files_scanned": files_scanned,
            "files_indexed": files_indexed,
            "indexed": files_indexed,
            "skipped": cache_hits,
            "cache_hits": cache_hits,
            "deleted_pruned": len(deleted_paths),
            "duration_ms": elapsed_ms,
        }

    def index_single_file(self, full_path: Path) -> bool:
        """Indexes a single file immediately."""
        full_path = full_path.resolve()
        ext = full_path.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS or not full_path.exists():
            return False

        try:
            rel_path = str(full_path.relative_to(self.workspace_root)).replace("\\", "/")
        except ValueError:
            rel_path = str(full_path).replace("\\", "/")

        self.db.init_schema()
        try:
            st = full_path.stat()
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return False

        content_hash = compute_file_hash(content)
        total_lines = content.count("\n") + 1
        lang = SUPPORTED_EXTENSIONS[ext]

        if lang == "python":
            symbols, imports, tests, references = parse_python_file(content, rel_path)
        else:
            symbols, imports, tests, references = parse_js_ts_file(content, rel_path)

        with self.db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM files WHERE path = ?", (rel_path,))
            cur.execute(
                "INSERT INTO files (path, mtime, size, hash, lang, total_lines) VALUES (?, ?, ?, ?, ?, ?)",
                (rel_path, st.st_mtime, st.st_size, content_hash, lang, total_lines),
            )
            file_id = cur.lastrowid
            for s in symbols:
                cur.execute(
                    "INSERT INTO symbols (file_id, name, container, type, line_start, line_end, signature, docstring) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (file_id, s["name"], s.get("container"), s["type"], s["line_start"], s["line_end"], s.get("signature"), s.get("docstring")),
                )
            for imp in imports:
                cur.execute(
                    "INSERT INTO imports (file_id, module, symbol, alias) VALUES (?, ?, ?, ?)",
                    (file_id, imp["module"], imp.get("symbol"), imp.get("alias")),
                )
            for t in tests:
                cur.execute(
                    "INSERT INTO tests (file_id, test_name, target_symbol, line) VALUES (?, ?, ?, ?)",
                    (file_id, t["test_name"], t.get("target_symbol"), t["line"]),
                )
            for r in references:
                cur.execute(
                    "INSERT INTO symbol_references (source_file_id, target_symbol, line) VALUES (?, ?, ?)",
                    (file_id, r["target_symbol"], r["line"]),
                )
            conn.commit()
        return True


# Global indexer instance & alias
codebase_indexer = CodebaseIndexer()
IncrementalIndexer = CodebaseIndexer

