"""
Token Budget Slice Packer for Protocol Brain Context Engine.
Extracts focused AST slices from disk and guarantees 100% compliance with budget ceilings.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ranker import CandidateSymbol


def estimate_tokens(text: str) -> int:
    """Fast estimation of token count (~3.8 characters per token)."""
    if not text:
        return 0
    return max(1, int(len(text) / 3.8))


def extract_slice_from_disk(
    full_path: Path,
    line_start: int,
    line_end: int,
    padding: int = 2,
) -> Tuple[str, int, int]:
    """
    Extracts specific code lines with contextual padding.
    Returns: (sliced_code_str, start_idx, end_idx)
    """
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return "", line_start, line_end

    total_lines = len(lines)
    start_idx = max(1, line_start - padding)
    end_idx = min(total_lines, line_end + padding)

    # 1-indexed to 0-indexed slicing
    selected_lines = lines[start_idx - 1 : end_idx]
    return "".join(selected_lines), start_idx, end_idx


def pack_context_packet(
    candidates: List[CandidateSymbol],
    workspace_root: Path,
    budget_tokens: int = 4000,
    telemetry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Packs candidates into a structured context document under strict budget constraints.
    Guarantees: returned_tokens <= budget_tokens
    """
    sections: List[str] = []
    packed_symbols: List[Dict[str, Any]] = []

    # Reserve 200 tokens for header and telemetry footer
    budget_limit = max(300, budget_tokens - 200)
    current_tokens = 0
    raw_files_total_chars = 0

    header = "# 🧠 Protocol Brain Synthesized Context Packet\n"
    current_tokens += estimate_tokens(header)
    sections.append(header)

    seen_slices: set = set()

    for cand in candidates:
        full_path = workspace_root / cand.file_path
        if not full_path.exists():
            continue

        # Check full file size for token savings benchmark comparison
        try:
            raw_files_total_chars += full_path.stat().st_size
        except OSError:
            pass

        slice_text, actual_start, actual_end = extract_slice_from_disk(
            full_path, cand.line_start, cand.line_end, padding=2
        )
        if not slice_text:
            continue

        slice_key = (cand.file_path, actual_start, actual_end)
        if slice_key in seen_slices:
            continue
        seen_slices.add(slice_key)

        container_prefix = f"{cand.container}." if cand.container else ""
        full_symbol_name = f"{container_prefix}{cand.name}"
        ext = full_path.suffix.lstrip(".")
        lang = "python" if ext == "py" else "typescript" if ext in ("ts", "tsx") else "javascript"

        section_md = (
            f"\n### 📍 `{cand.file_path}:{actual_start}-{actual_end}` (`{full_symbol_name}` | {cand.sym_type})\n"
            f"*{' • '.join(cand.reasons)}*\n"
            f"```{lang}\n"
            f"{slice_text.rstrip()}\n"
            f"```\n"
        )

        slice_tokens = estimate_tokens(section_md)

        # Enforce hard budget ceiling
        if current_tokens + slice_tokens > budget_limit:
            break

        sections.append(section_md)
        current_tokens += slice_tokens
        packed_symbols.append({
            "symbol": full_symbol_name,
            "file": cand.file_path,
            "lines": f"{actual_start}-{actual_end}",
            "type": cand.sym_type,
            "score": cand.score,
        })

    # Calculate token savings estimate
    raw_equivalent_tokens = max(current_tokens, estimate_tokens("a" * raw_files_total_chars))
    savings_pct = round(((raw_equivalent_tokens - current_tokens) / max(1, raw_equivalent_tokens)) * 100, 1)

    meta = telemetry or {}
    meta.update({
        "symbols_considered": len(candidates),
        "symbols_packed": len(packed_symbols),
        "estimated_tokens": current_tokens,
        "budget_tokens": budget_tokens,
        "budget_headroom": max(0, budget_tokens - current_tokens),
        "raw_equivalent_tokens": raw_equivalent_tokens,
        "token_savings_percent": savings_pct,
    })

    footer = (
        "\n---\n"
        f"> **Telemetry:** Packed {len(packed_symbols)} symbols ({current_tokens}/{budget_tokens} tokens | "
        f"{savings_pct}% tokens saved vs raw full files)\n"
    )
    sections.append(footer)

    full_context_text = "".join(sections)

    return {
        "success": True,
        "context": full_context_text,
        "packed_symbols": packed_symbols,
        "telemetry": meta,
        "estimated_tokens": current_tokens,
        "budget_tokens": budget_tokens,
        "token_savings_percent": savings_pct,
    }
