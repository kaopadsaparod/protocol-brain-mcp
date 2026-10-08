"""
AST Code Outline and Symbol Extraction Module.
Allows agents to read only the specific symbols they need, cutting token usage drastically.
"""

import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger


def parse_python_outline(file_path: Path) -> List[Dict[str, Any]]:
    """Parse Python code using built-in ast for high accuracy and speed."""
    symbols = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=str(file_path))

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                methods = []
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods.append({
                            "name": child.name,
                            "line": child.lineno,
                            "end_line": getattr(child, "end_lineno", child.lineno),
                            "type": "async_method" if isinstance(child, ast.AsyncFunctionDef) else "method",
                            "args": [arg.arg for arg in child.args.args],
                        })
                symbols.append({
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "type": "class",
                    "methods": methods,
                })
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append({
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "type": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                    "args": [arg.arg for arg in node.args.args],
                })
    except Exception as e:
        logger.warning(f"AST Parse warning for {file_path}: {e}")
        symbols.append({"error": f"AST Parse error: {e}"})
    return symbols


def parse_js_ts_outline(file_path: Path) -> List[Dict[str, Any]]:
    """Parse JS/TS files using pattern matching for functions, classes, and interfaces."""
    symbols = []
    patterns = [
        (re.compile(r"^\s*(export\s+)?class\s+([A-Za-z0-9_$]+)"), "class"),
        (re.compile(r"^\s*(export\s+)?interface\s+([A-Za-z0-9_$]+)"), "interface"),
        (re.compile(r"^\s*(export\s+)?type\s+([A-Za-z0-9_$]+)\s*="), "type"),
        (re.compile(r"^\s*(export\s+)?(async\s+)?function\s+([A-Za-z0-9_$]+)"), "function"),
        (re.compile(r"^\s*(export\s+)?(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s*)?\("), "arrow_function"),
    ]

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for pattern, symbol_type in patterns:
                m = pattern.search(line)
                if m:
                    groups = [g for g in m.groups() if g and g not in ("export", "async", "const", "let", "var")]
                    name = groups[-1] if groups else m.group(0).strip()
                    symbols.append({
                        "name": name,
                        "line": idx,
                        "type": symbol_type,
                        "signature": stripped[:120],
                    })
                    break
    except Exception as e:
        symbols.append({"error": f"Parse error: {e}"})
    return symbols


def get_code_outline(file_path_str: str) -> Dict[str, Any]:
    """
    Get a high-signal outline of a code file without reading its entire content.
    Saves massive tokens for coding agents.
    """
    target = Path(file_path_str)
    if not target.exists() or not target.is_file():
        return {
            "success": False,
            "error": f"File '{file_path_str}' does not exist.",
            "actionable_hint": "Verify the file path. Check for case sensitivity or typo in filename.",
            "file": file_path_str,
            "symbols": [],
        }

    ext = target.suffix.lower()
    total_lines = 0
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            total_lines = sum(1 for _ in f)
    except Exception:
        pass

    if ext == ".py":
        symbols = parse_python_outline(target)
    elif ext in [".ts", ".tsx", ".js", ".jsx", ".mjs"]:
        symbols = parse_js_ts_outline(target)
    else:
        return {
            "success": False,
            "error": f"File extension '{ext}' is not supported for outline extraction.",
            "actionable_hint": "Supported extensions: .py, .js, .ts, .tsx, .jsx",
            "file": str(target),
            "symbols": [],
        }

    return {
        "success": True,
        "file": str(target),
        "extension": ext,
        "total_lines": total_lines,
        "symbol_count": len(symbols),
        "symbols": symbols,
    }


def read_python_symbol(source: str, symbol_name: str, file_path: Path) -> Optional[Dict[str, Any]]:
    """Extract a specific class, function, or method definition from Python source."""
    tree = ast.parse(source, filename=str(file_path))
    lines = source.splitlines(keepends=True)

    # Check for ClassName.method_name format
    target_class = None
    target_method = symbol_name
    if "." in symbol_name:
        parts = symbol_name.split(".", 1)
        target_class = parts[0]
        target_method = parts[1]

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            if target_class:
                if node.name == target_class:
                    for child in node.body:
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == target_method:
                            start = child.lineno - 1
                            end = getattr(child, "end_lineno", len(lines))
                            code = "".join(lines[start:end])
                            return {
                                "name": f"{node.name}.{child.name}",
                                "type": "method",
                                "line_start": child.lineno,
                                "line_end": getattr(child, "end_lineno", child.lineno),
                                "docstring": ast.get_docstring(child),
                                "code": code,
                            }
            elif node.name == symbol_name:
                start = node.lineno - 1
                end = getattr(node, "end_lineno", len(lines))
                code = "".join(lines[start:end])
                return {
                    "name": node.name,
                    "type": "class",
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "docstring": ast.get_docstring(node),
                    "code": code,
                }
            else:
                # Also search methods directly if user didn't specify ClassName.
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == symbol_name:
                        start = child.lineno - 1
                        end = getattr(child, "end_lineno", len(lines))
                        code = "".join(lines[start:end])
                        return {
                            "name": f"{node.name}.{child.name}",
                            "type": "method",
                            "line_start": child.lineno,
                            "line_end": getattr(child, "end_lineno", child.lineno),
                            "docstring": ast.get_docstring(child),
                            "code": code,
                        }
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol_name:
            start = node.lineno - 1
            end = getattr(node, "end_lineno", len(lines))
            code = "".join(lines[start:end])
            return {
                "name": node.name,
                "type": "function",
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno),
                "docstring": ast.get_docstring(node),
                "code": code,
            }
    return None


def read_js_ts_symbol(lines: List[str], symbol_name: str) -> Optional[Dict[str, Any]]:
    """Extract a JS/TS function or class by matching braces block."""
    target_pattern = re.compile(rf"\b(function|class|interface|type|const|let|var)\s+{re.escape(symbol_name)}\b")

    start_line = -1
    for idx, line in enumerate(lines):
        if target_pattern.search(line):
            start_line = idx
            break

    if start_line == -1:
        return None

    # Track braces to find end of block
    brace_count = 0
    started_braces = False
    end_line = start_line

    for idx in range(start_line, len(lines)):
        line = lines[idx]
        brace_count += line.count("{") - line.count("}")
        if "{" in line:
            started_braces = True
        end_line = idx
        if started_braces and brace_count <= 0:
            break
        # Fallback limit: don't exceed 200 lines
        if idx - start_line > 200:
            break

    code = "".join(lines[start_line : end_line + 1])
    return {
        "name": symbol_name,
        "type": "js_ts_symbol",
        "line_start": start_line + 1,
        "line_end": end_line + 1,
        "code": code,
    }


def read_symbol(file_path_str: str, symbol_name: str) -> Dict[str, Any]:
    """
    Extract ONLY the specified function, class, or method definition from a source file.
    This delivers maximum token savings by returning exactly what is requested without the rest of the file.
    """
    target = Path(file_path_str)
    if not target.exists() or not target.is_file():
        return {
            "success": False,
            "error": f"File '{file_path_str}' does not exist.",
            "actionable_hint": "Check the path or use find_references to find where the symbol lives.",
        }

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        ext = target.suffix.lower()
        result = None

        if ext == ".py":
            result = read_python_symbol(content, symbol_name, target)
        elif ext in [".ts", ".tsx", ".js", ".jsx", ".mjs"]:
            lines = content.splitlines(keepends=True)
            result = read_js_ts_symbol(lines, symbol_name)

        if result:
            return {
                "success": True,
                "file": str(target),
                "symbol": result,
            }
        else:
            return {
                "success": False,
                "error": f"Symbol '{symbol_name}' not found in '{target.name}'.",
                "actionable_hint": f"Run 'get_file_outline(\"{file_path_str}\")' to view all available symbols in this file.",
            }
    except Exception as e:
        logger.error(f"Error in read_symbol for {file_path_str} / {symbol_name}: {e}")
        return {
            "success": False,
            "error": f"Failed to extract symbol: {e}",
            "actionable_hint": "Ensure the file contains valid syntax.",
        }
