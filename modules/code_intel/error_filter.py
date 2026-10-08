import re
from typing import Any, Dict, List


def filter_build_errors(raw_log: str, max_lines: int = 30) -> Dict[str, Any]:
    """
    Parses build, compile, or test output and removes boilerplate/bundler noise.
    Extracts only failing assertions, error messages, and stack traces.
    """
    if not raw_log:
        return {"has_errors": False, "summary": "No output provided", "clean_errors": []}

    lines = raw_log.splitlines()
    error_patterns = [
        re.compile(r"error[:\s]", re.IGNORECASE),
        re.compile(r"fail(ed|ure)?[:\s]", re.IGNORECASE),
        re.compile(r"exception[:\s]", re.IGNORECASE),
        re.compile(r"traceback", re.IGNORECASE),
        re.compile(r"syntaxerror", re.IGNORECASE),
        re.compile(r"typeerror", re.IGNORECASE),
        re.compile(r"assertionerror", re.IGNORECASE),
        re.compile(r"ts\d{4}:", re.IGNORECASE),  # TypeScript error codes
    ]

    selected_lines: List[str] = []
    capture_context = 0

    for line in lines:
        stripped = line.strip()
        is_error_trigger = any(p.search(stripped) for p in error_patterns)

        if is_error_trigger:
            selected_lines.append(line)
            capture_context = 3  # Capture next 3 lines of stack trace
        elif capture_context > 0:
            selected_lines.append(line)
            capture_context -= 1

        if len(selected_lines) >= max_lines:
            selected_lines.append(f"... [Truncated {len(lines) - len(selected_lines)} noisy lines]")
            break

    has_errors = len(selected_lines) > 0
    clean_text = "\n".join(selected_lines) if has_errors else raw_log[:1500]

    return {
        "has_errors": has_errors,
        "original_line_count": len(lines),
        "filtered_line_count": len(selected_lines),
        "clean_output": clean_text,
    }
