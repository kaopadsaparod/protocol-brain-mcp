"""
Codebase Reasoning & Architectural Q&A for Protocol Brain Context Engine.
Synthesizes end-to-end execution flows and diagnoses system questions deterministically
under a strict token budget.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from ..security import redact_secrets
from .call_graph import get_call_graph
from .indexer import IncrementalIndexer
from .packer import estimate_tokens, extract_slice_from_disk
from .ranker import tokenize_query
from .storage import IndexStorage


def answer_port_question(question: str) -> Optional[Dict[str, Any]]:
    """Answers questions regarding busy or conflicting network ports."""
    port_match = re.search(r"\bport\s*[:=]?\s*(\d{2,5})\b", question.lower())
    if not port_match and not any(w in question.lower() for w in ("port", "ชน", "busy", "conflict")):
        return None

    target_port = int(port_match.group(1)) if port_match else None

    # Search listening ports
    matched_services = []
    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                p_num = conn.laddr.port
                if target_port is None or p_num == target_port:
                    pid = conn.pid
                    proc_name = "unknown"
                    parent_name = "unknown"
                    cmd_line = ""
                    if pid:
                        try:
                            p = psutil.Process(pid)
                            proc_name = p.name()
                            cmd_line = redact_secrets(" ".join(p.cmdline()[:4]))
                            if p.parent():
                                parent_name = p.parent().name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    matched_services.append({
                        "port": p_num,
                        "pid": pid,
                        "process": proc_name,
                        "parent": parent_name,
                        "cmd": cmd_line,
                    })
    except Exception:
        pass

    if target_port and not matched_services:
        md = f"### 🌐 Port {target_port} Diagnosis\nPort `{target_port}` is currently **available** (no active listening processes detected on localhost)."
        return {"category": "PORT_DIAGNOSIS", "answer_markdown": md, "services": []}

    md_lines = ["### 🌐 Port Conflict Diagnosis"]
    for s in matched_services[:5]:
        md_lines.append(
            f"- **Port {s['port']}** is held by PID `{s['pid']}` (`{s['process']}`)\n"
            f"  - Parent process: `{s['parent']}`\n"
            f"  - Command line: `{s['cmd']}`\n"
            f"  - Solution: Call `release_port(port={s['port']})` to terminate."
        )

    return {
        "category": "PORT_DIAGNOSIS",
        "answer_markdown": "\n".join(md_lines),
        "services": matched_services,
    }


def ask_codebase(
    question: str,
    budget_tokens: int = 3500,
    workspace_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Answers high-level architectural and operational questions about the codebase
    by synthesizing execution flows and targeted AST slices under a strict token budget.
    """
    if not question or not question.strip():
        return {
            "success": False,
            "error": "Question cannot be empty.",
            "actionable_hint": "Ask an architectural or operational question (e.g. 'how does authentication work?' or 'why is port 3000 busy?').",
        }

    # 1. Check for runtime port questions
    port_ans = answer_port_question(question)
    if port_ans:
        return {
            "success": True,
            "question": question,
            "category": "RUNTIME_PORT",
            "answer_markdown": port_ans["answer_markdown"],
            "flow_steps": [],
            "estimated_tokens": estimate_tokens(port_ans["answer_markdown"]),
        }

    # 2. Architectural Flow Extraction
    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    storage = IndexStorage(root_dir=root)
    indexer = IncrementalIndexer(workspace_root=root, storage=storage)
    indexer.index_workspace(max_depth=3)

    tokens = tokenize_query(question)
    conn = storage.get_connection()
    cur = conn.cursor()

    # Find primary matching symbols
    matched_symbols: List[Dict[str, Any]] = []
    for tok in list(tokens)[:4]:
        cur.execute("""
            SELECT s.name, s.type, s.line_start, s.line_end, f.path
            FROM symbols s
            JOIN files f ON s.file_id = f.id
            WHERE s.name LIKE ? OR s.container LIKE ?
            ORDER BY (s.line_end - s.line_start) ASC
            LIMIT 5
        """, (f"%{tok}%", f"%{tok}%"))
        for s_name, s_type, ls, le, fp in cur.fetchall():
            if not any(ms["name"] == s_name for ms in matched_symbols):
                matched_symbols.append({
                    "name": s_name,
                    "type": s_type,
                    "line_start": ls,
                    "line_end": le,
                    "file_path": fp,
                })

    flow_steps: List[Dict[str, Any]] = []
    budget_limit = max(300, budget_tokens - 200)
    current_tokens = 0
    md_sections = [f"# 🧠 Protocol Brain Architectural Flow: \"{question}\"\n"]

    if matched_symbols:
        # Use first matched symbol as root of flow
        root_sym = matched_symbols[0]
        call_tree = get_call_graph(root_sym["name"], depth=2, direction="downstream", workspace_root=root)

        md_sections.append("### 🗺️ High-Level Execution Tree")
        md_sections.append(call_tree.get("tree_markdown", ""))
        current_tokens += estimate_tokens(md_sections[-1])

        md_sections.append("\n### 📍 Key Pipeline Stages & Slices")

        for sym in matched_symbols[:3]:
            f_path = root / sym["file_path"]
            if f_path.exists():
                slice_code, a_start, a_end = extract_slice_from_disk(f_path, sym["line_start"], sym["line_end"], padding=2)
                if slice_code:
                    ext = f_path.suffix.lstrip(".")
                    lang = "python" if ext == "py" else "typescript" if ext in ("ts", "tsx") else "javascript"
                    stage_md = (
                        f"\n#### Stage: `{sym['name']}()` (`{sym['file_path']}:{a_start}-{a_end}`)\n"
                        f"```{lang}\n{slice_code.rstrip()}\n```\n"
                    )
                    stage_tokens = estimate_tokens(stage_md)
                    if current_tokens + stage_tokens > budget_limit:
                        break
                    md_sections.append(stage_md)
                    current_tokens += stage_tokens
                    flow_steps.append({
                        "symbol": sym["name"],
                        "file": sym["file_path"],
                        "lines": f"{a_start}-{a_end}",
                    })
    else:
        md_sections.append("*(No specific architectural symbols matched the query tokens in the indexed codebase)*")

    answer_text = "\n".join(md_sections)
    final_tokens = estimate_tokens(answer_text)

    return {
        "success": True,
        "question": question,
        "category": "ARCHITECTURAL_FLOW",
        "answer_markdown": answer_text,
        "flow_steps": flow_steps,
        "relevant_symbols_count": len(matched_symbols),
        "estimated_tokens": final_tokens,
        "budget_tokens": budget_tokens,
    }
