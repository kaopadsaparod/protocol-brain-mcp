"""
Error Tracer for Protocol Brain Context Engine.
Analyzes stack traces, maps error locations to AST symbols, extracts crash site slices,
identifies callers and related tests, and packs focused diagnostic context for Terminal AI.
Zero-LLM deterministic parsing.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .indexer import IncrementalIndexer
from .packer import estimate_tokens, extract_slice_from_disk
from .storage import IndexStorage


class StackFrame:
    def __init__(self, file_path: str, line_number: int, symbol_name: str, raw_line: str, is_project_file: bool = False):
        self.file_path = file_path
        self.line_number = line_number
        self.symbol_name = symbol_name
        self.raw_line = raw_line
        self.is_project_file = is_project_file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "symbol": self.symbol_name,
            "is_project": self.is_project_file,
        }


def parse_stack_trace(error_text: str, workspace_root: Path) -> Dict[str, Any]:
    """
    Parses Python tracebacks, Node/TS stack traces, Go panics, and generic file:line logs.
    """
    frames: List[StackFrame] = []
    error_type = "UnknownError"
    error_message = ""

    lines = error_text.strip().splitlines()

    # 1. Detect Python Traceback
    # File "...", line 123, in func_name
    py_frame_pattern = re.compile(r'File\s+["\']([^"\']+)["\'],\s+line\s+(\d+)(?:,\s+in\s+([^\n\r]+))?')

    # 2. Detect Node.js / TypeScript Stack Trace
    # at symbol (path:line:col) OR at path:line:col
    node_frame_pattern = re.compile(r'at\s+(?:([^\s(]+)\s+\()?([a-zA-Z]:[\\/][^:()]+|/[^:()]+|[^:()\s]+):(\d+)(?::\d+)?\)?')

    # 3. Detect Generic file:line pattern
    # path/to/file.ext:123
    generic_frame_pattern = re.compile(r'(?:^|\s)([a-zA-Z0-9_\-\./\\]+\.[a-zA-Z0-9]+):(\d+)')

    # Check for error type and message at the end or beginning
    for line in lines:
        line_clean = line.strip()
        # Common Python exceptions (e.g., ValueError: message)
        py_exc_match = re.match(r'^([A-Z][a-zA-Z0-9_]*(?:Error|Exception|Warning|Interrupt|Exit)):?\s*(.*)$', line_clean)
        if py_exc_match:
            error_type = py_exc_match.group(1)
            error_message = py_exc_match.group(2)
            continue

        # Common JS/TS exceptions (e.g., TypeError: Cannot read properties...)
        js_exc_match = re.match(r'^([A-Z][a-zA-Z0-9_]*Error):\s*(.*)$', line_clean)
        if js_exc_match:
            error_type = js_exc_match.group(1)
            error_message = js_exc_match.group(2)
            continue

        # Go panic (e.g., panic: runtime error: ...)
        go_panic_match = re.match(r'^panic:\s*(.*)$', line_clean)
        if go_panic_match:
            error_type = "Panic"
            error_message = go_panic_match.group(1)
            continue

    # Parse frames
    for raw_line in lines:
        raw_clean = raw_line.strip()

        # Python
        m_py = py_frame_pattern.search(raw_clean)
        if m_py:
            fpath, line_str, sym = m_py.group(1), m_py.group(2), m_py.group(3) or "module"
            is_proj = _is_workspace_path(fpath, workspace_root)
            norm_path = _normalize_path(fpath, workspace_root)
            frames.append(StackFrame(norm_path, int(line_str), sym.strip(), raw_clean, is_proj))
            continue

        # Node / TS
        m_node = node_frame_pattern.search(raw_clean)
        if m_node:
            sym, fpath, line_str = m_node.group(1) or "anonymous", m_node.group(2), m_node.group(3)
            is_proj = _is_workspace_path(fpath, workspace_root)
            norm_path = _normalize_path(fpath, workspace_root)
            frames.append(StackFrame(norm_path, int(line_str), sym.strip(), raw_clean, is_proj))
            continue

        # Generic
        m_gen = generic_frame_pattern.search(raw_clean)
        if m_gen and not raw_clean.startswith("at "):
            fpath, line_str = m_gen.group(1), m_gen.group(2)
            if any(fpath.endswith(ext) for ext in [".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs"]):
                is_proj = _is_workspace_path(fpath, workspace_root)
                norm_path = _normalize_path(fpath, workspace_root)
                frames.append(StackFrame(norm_path, int(line_str), "unknown", raw_clean, is_proj))

    # If no explicit error message found, use the last non-empty line
    if not error_message and lines:
        for line_item in reversed(lines):
            item_clean = line_item.strip()
            if item_clean and not item_clean.startswith("at ") and not item_clean.startswith("File "):
                error_message = item_clean
                break

    return {
        "error_type": error_type,
        "error_message": error_message,
        "frames": frames,
    }


def _is_workspace_path(fpath: str, workspace_root: Path) -> bool:
    """Checks if a frame path belongs to the active workspace rather than third-party deps."""
    fpath_lower = fpath.lower().replace("\\", "/")
    if "node_modules" in fpath_lower or "site-packages" in fpath_lower or "/dist/" in fpath_lower:
        return False
    try:
        p = Path(fpath)
        if not p.is_absolute():
            # Relative path within workspace
            return (workspace_root / p).exists()
        return workspace_root in p.parents or p == workspace_root
    except Exception:
        return False


def _normalize_path(fpath: str, workspace_root: Path) -> str:
    """Normalizes path relative to workspace root if possible."""
    try:
        p = Path(fpath)
        if p.is_absolute():
            rel = p.relative_to(workspace_root)
            return str(rel).replace("\\", "/")
        return str(p).replace("\\", "/")
    except Exception:
        return fpath.replace("\\", "/")


def trace_error(
    error_log: str,
    workspace_root: Optional[str] = None,
    budget_tokens: int = 3000,
) -> Dict[str, Any]:
    """
    Parses an error log or stack trace, locates the crash site in workspace source code,
    retrieves the code slice, callers, and relevant tests, and produces a focused diagnostic context.
    """
    if not error_log or not error_log.strip():
        return {
            "success": False,
            "error": "Empty error log provided.",
            "actionable_hint": "Pass the full traceback, stack trace, or error log string into trace_error.",
        }

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    parsed = parse_stack_trace(error_log, root)
    frames: List[StackFrame] = parsed["frames"]

    # Filter for project frames
    project_frames = [f for f in frames if f.is_project_file]
    # The primary crash site in project code is usually the deepest project frame
    crash_site = project_frames[-1] if project_frames else (frames[-1] if frames else None)

    # Initialize storage and indexer to find symbol details
    storage = IndexStorage()
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)

    crash_code_slice = ""
    crash_symbol_info = None
    callers: List[str] = []
    relevant_tests: List[str] = []

    if crash_site:
        crash_file = root / crash_site.file_path
        if crash_file.exists():
            # Index file if not yet up to date
            indexer.index_single_file(crash_file)

            conn = storage.get_connection()
            cur = conn.cursor()

            # Find matching symbol in crash file containing the crash line
            cur.execute("""
                SELECT s.name, s.type, s.line_start, s.line_end, s.container
                FROM symbols s
                JOIN files f ON s.file_id = f.id
                WHERE f.path = ? AND s.line_start <= ? AND s.line_end >= ?
                ORDER BY (s.line_end - s.line_start) ASC
                LIMIT 1
            """, (crash_site.file_path, crash_site.line_number, crash_site.line_number))
            row = cur.fetchone()

            if row:
                sym_name, sym_type, l_start, l_end, container = row
                crash_symbol_info = {
                    "name": sym_name,
                    "type": sym_type,
                    "container": container,
                    "lines": f"{l_start}-{l_end}",
                }
                crash_code_slice, start_l, end_l = extract_slice_from_disk(
                    crash_file, l_start, l_end, padding=2
                )
                # Find callers of this symbol
                cur.execute("""
                    SELECT f.path, sr.line
                    FROM symbol_references sr
                    JOIN files f ON sr.source_file_id = f.id
                    WHERE sr.target_symbol = ? AND f.path != ?
                    LIMIT 5
                """, (sym_name, crash_site.file_path))
                callers = [f"{r[0]}:{r[1]}" for r in cur.fetchall()]
            else:
                # If no enclosing symbol, slice around the crash line
                crash_code_slice, start_l, end_l = extract_slice_from_disk(
                    crash_file, max(1, crash_site.line_number - 8), crash_site.line_number + 8, padding=0
                )

            # Look up tests referencing this file or symbol
            cur.execute("""
                SELECT f.path, t.test_name
                FROM tests t
                JOIN files f ON t.file_id = f.id
                WHERE f.path LIKE '%test%' OR t.test_name LIKE ?
                LIMIT 5
            """, (f"%{crash_site.file_path.split('/')[-1].split('.')[0]}%",))
            relevant_tests = [f"{r[0]} ({r[1]})" for r in cur.fetchall()]

    # Construct synthesized markdown context under budget
    md_sections = [
        f"# 🚨 Diagnostic Crash Trace: `{parsed['error_type']}`",
        f"- **Message:** `{parsed['error_message']}`",
    ]

    if crash_site:
        md_sections.append(f"- **Crash Location:** `{crash_site.file_path}:{crash_site.line_number}`")
        if crash_symbol_info:
            md_sections.append(f"- **Symbol:** `{crash_symbol_info['name']}` ({crash_symbol_info['type']})")
    else:
        md_sections.append("- **Crash Location:** Could not pinpoint project source location.")

    if crash_code_slice and crash_site:
        ext = Path(crash_site.file_path).suffix.lstrip(".")
        lang = "python" if ext == "py" else "typescript" if ext in ("ts", "tsx") else "javascript"
        md_sections.append(f"\n### 📍 Crash Site Source (`{crash_site.file_path}:{crash_site.line_number}`)")
        md_sections.append(f"```{lang}\n{crash_code_slice.rstrip()}\n```")

    if callers:
        md_sections.append("\n### 🔗 Callers & Inbound Usages")
        for c in callers:
            md_sections.append(f"- `{c}`")

    if relevant_tests:
        md_sections.append("\n### 🧪 Related Test Cases")
        for t in relevant_tests:
            md_sections.append(f"- `{t}`")

    md_sections.append("\n### 💡 Actionable Recommendation")
    if "NoneType" in parsed["error_message"] or "undefined" in parsed["error_message"] or "NullPointer" in parsed["error_type"]:
        md_sections.append(f"- Check for null/None guard around variable dereference near line {crash_site.line_number if crash_site else '?'}.")
    elif "IndexError" in parsed["error_type"] or "index out of range" in parsed["error_message"]:
        md_sections.append(f"- Verify list/array boundary check before accessing index near line {crash_site.line_number if crash_site else '?'}.")
    elif "KeyError" in parsed["error_type"]:
        md_sections.append(f"- Use `.get()` or check key presence with `in` dictionary near line {crash_site.line_number if crash_site else '?'}.")
    else:
        md_sections.append(f"- Inspect input parameters passed into `{crash_symbol_info['name'] if crash_symbol_info else 'calling frame'}`.")

    synthesized_md = "\n".join(md_sections)
    estimated_tokens = estimate_tokens(synthesized_md)

    return {
        "success": True,
        "diagnostic_context": synthesized_md,
        "error_type": parsed["error_type"],
        "error_message": parsed["error_message"],
        "crash_site": crash_site.to_dict() if crash_site else None,
        "crash_symbol": crash_symbol_info,
        "callers": callers,
        "related_tests": relevant_tests,
        "stack_frames_count": len(frames),
        "project_frames_count": len(project_frames),
        "estimated_tokens": estimated_tokens,
    }
