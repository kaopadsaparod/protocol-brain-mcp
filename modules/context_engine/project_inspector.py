"""
Project Inspector for Protocol Brain Context Engine.
Generates instant architectural blueprints, dependency graphs, and entry points for Terminal AI.
Zero LLM, purely deterministic file and AST analysis.
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logger import logger
from .storage import IndexStorage


def detect_languages_and_tools(root: Path) -> Dict[str, Any]:
    """Detects languages, package managers, test runners, and key config files."""
    languages: List[str] = []
    tooling: List[str] = []
    frameworks: List[str] = []
    test_runners: List[str] = []
    configs: List[str] = []

    # Python
    pyproject = root / "pyproject.toml"
    reqs = root / "requirements.txt"
    setup_py = root / "setup.py"
    if pyproject.exists() or reqs.exists() or setup_py.exists() or any(root.glob("*.py")):
        languages.append("Python")
        if (root / "poetry.lock").exists():
            tooling.append("Poetry")
        elif (root / "uv.lock").exists():
            tooling.append("uv")
        elif (root / "Pipfile").exists():
            tooling.append("Pipenv")
        else:
            tooling.append("pip")

        # Pytest detection
        if (root / "pytest.ini").exists() or (root / "conftest.py").exists() or (root / "tests").exists():
            test_runners.append("pytest")

        # Inspect requirements / pyproject for common frameworks
        content = ""
        if pyproject.exists():
            configs.append("pyproject.toml")
            try:
                content += pyproject.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
        if reqs.exists():
            configs.append("requirements.txt")
            try:
                content += reqs.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass

        content_lower = content.lower()
        if "fastapi" in content_lower:
            frameworks.append("FastAPI")
        if "flask" in content_lower:
            frameworks.append("Flask")
        if "django" in content_lower:
            frameworks.append("Django")
        if "mcp" in content_lower:
            frameworks.append("MCP (Model Context Protocol)")
        if "pydantic" in content_lower:
            frameworks.append("Pydantic")
        if "pytest" in content_lower and "pytest" not in test_runners:
            test_runners.append("pytest")
        if "ruff" in content_lower:
            tooling.append("ruff")

    # JavaScript / TypeScript
    pkg_json = root / "package.json"
    if pkg_json.exists() or (root / "tsconfig.json").exists() or any(root.glob("*.ts")) or any(root.glob("*.js")):
        if (root / "tsconfig.json").exists():
            languages.append("TypeScript")
            configs.append("tsconfig.json")
        else:
            languages.append("JavaScript")

        if (root / "pnpm-lock.yaml").exists():
            tooling.append("pnpm")
        elif (root / "yarn.lock").exists():
            tooling.append("yarn")
        elif (root / "bun.lockb").exists() or (root / "bun.lock").exists():
            tooling.append("bun")
        elif pkg_json.exists():
            tooling.append("npm")

        if pkg_json.exists():
            configs.append("package.json")
            try:
                pkg_data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                deps = {
                    **pkg_data.get("dependencies", {}),
                    **pkg_data.get("devDependencies", {}),
                }
                deps_lower = {k.lower(): v for k, v in deps.items()}
                if "next" in deps_lower:
                    frameworks.append("Next.js")
                if "react" in deps_lower and "Next.js" not in frameworks:
                    frameworks.append("React")
                if "vue" in deps_lower:
                    frameworks.append("Vue")
                if "express" in deps_lower:
                    frameworks.append("Express")
                if "vitest" in deps_lower:
                    test_runners.append("vitest")
                elif "jest" in deps_lower:
                    test_runners.append("jest")
            except Exception:
                pass

    # Rust
    if (root / "Cargo.toml").exists():
        languages.append("Rust")
        tooling.append("cargo")
        test_runners.append("cargo test")
        configs.append("Cargo.toml")

    # Go
    if (root / "go.mod").exists():
        languages.append("Go")
        tooling.append("go")
        test_runners.append("go test")
        configs.append("go.mod")

    # Docker
    if (root / "Dockerfile").exists() or (root / "docker-compose.yml").exists() or (root / "compose.yaml").exists():
        tooling.append("Docker")

    return {
        "languages": list(dict.fromkeys(languages)),
        "frameworks": list(dict.fromkeys(frameworks)),
        "tooling": list(dict.fromkeys(tooling)),
        "test_runners": list(dict.fromkeys(test_runners)),
        "config_files": list(dict.fromkeys(configs)),
    }


def find_entry_points(root: Path) -> List[str]:
    """Detects primary entry points and startup files."""
    candidates = [
        "server.py", "main.py", "app.py", "run.py", "cli.py", "index.py",
        "index.ts", "index.js", "src/main.rs", "cmd/main.go", "src/index.ts",
        "src/app.ts", "src/server.ts", "src/main.ts",
    ]
    found = []
    for cand in candidates:
        if (root / cand).exists():
            found.append(cand.replace("\\", "/"))

    # Also check package.json scripts
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            scripts = data.get("scripts", {})
            for key in ["start", "dev", "build", "test"]:
                if key in scripts:
                    found.append(f"npm run {key} -> {scripts[key]}")
        except Exception:
            pass

    return found


def generate_directory_tree(root: Path, max_depth: int = 2) -> str:
    """Generates a compact, readable ASCII tree skipping noisy directories."""
    ignore_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
        ".protocol_brain", ".pytest_cache", ".ruff_cache", ".mypy_cache", "coverage",
        ".gemini", ".idea", ".vscode",
    }

    lines = [f"{root.name}/"]

    def walk(current_dir: Path, prefix: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(list(current_dir.iterdir()), key=lambda e: (not e.is_dir(), e.name.lower()))
        except OSError:
            return

        visible_entries = [e for e in entries if e.name not in ignore_dirs and not e.name.startswith(".")]

        for i, entry in enumerate(visible_entries):
            is_last = (i == len(visible_entries) - 1)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            if entry.is_dir():
                lines.append(f"{prefix}{connector}{entry.name}/")
                walk(entry, prefix + child_prefix, depth + 1)
            else:
                lines.append(f"{prefix}{connector}{entry.name}")

    walk(root, "", 1)
    return "\n".join(lines[:60])  # Cap at 60 lines for token frugality


def get_git_quick_summary(root: Path) -> Dict[str, Any]:
    """Gets branch and dirty status without blocking."""
    try:
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"],
            cwd=str(root),
            stderr=subprocess.DEVNULL,
            timeout=2,
            text=True,
        ).strip()
    except Exception:
        branch = "unknown"

    try:
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(root),
            stderr=subprocess.DEVNULL,
            timeout=2,
            text=True,
        )
        dirty_count = len([line for line in status_out.splitlines() if line.strip()])
    except Exception:
        dirty_count = 0

    return {
        "branch": branch or "detached/unknown",
        "dirty_files": dirty_count,
        "is_clean": dirty_count == 0,
    }


def inspect_project(
    workspace_root: Optional[str] = None,
    max_depth: int = 2,
) -> Dict[str, Any]:
    """
    Synthesizes an immediate architectural blueprint and stack overview of the workspace.
    Returns:
        Structured blueprint dictionary with markdown preview and telemetry.
    """
    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    if not root.exists() or not root.is_dir():
        return {
            "success": False,
            "error": f"Invalid workspace root: {root}",
            "actionable_hint": "Provide a valid existing directory path.",
        }

    tech = detect_languages_and_tools(root)
    entry_points = find_entry_points(root)
    tree_str = generate_directory_tree(root, max_depth=max_depth)
    git_info = get_git_quick_summary(root)

    # Check local index stats if storage exists
    index_stats = {"indexed_files": 0, "indexed_symbols": 0}
    try:
        storage = IndexStorage()
        conn = storage.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM files")
        index_stats["indexed_files"] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM symbols")
        index_stats["indexed_symbols"] = cur.fetchone()[0]
    except Exception as e:
        logger.debug(f"Index stats lookup skipped: {e}")

    # Build concise markdown blueprint
    md_lines = [
        f"# 🏗️ Project Architecture Blueprint: `{root.name}`",
        f"- **Path:** `{root}`",
        f"- **Languages:** {', '.join(tech['languages']) or 'Not detected'}",
        f"- **Frameworks:** {', '.join(tech['frameworks']) or 'None'}",
        f"- **Tooling / PM:** {', '.join(tech['tooling']) or 'Standard'}",
        f"- **Test Runners:** {', '.join(tech['test_runners']) or 'None detected'}",
        f"- **Git Status:** branch `{git_info['branch']}` ({git_info['dirty_files']} modified files)",
        f"- **Context Index:** {index_stats['indexed_files']} files, {index_stats['indexed_symbols']} symbols indexed",
        "\n### 🚀 Key Entry Points",
    ]
    if entry_points:
        for ep in entry_points:
            md_lines.append(f"- `{ep}`")
    else:
        md_lines.append("- *(No standard entry point files recognized)*")

    md_lines.append("\n### 📂 Directory Map")
    md_lines.append("```text")
    md_lines.append(tree_str)
    md_lines.append("```")

    blueprint_md = "\n".join(md_lines)

    return {
        "success": True,
        "blueprint_markdown": blueprint_md,
        "project_name": root.name,
        "workspace_root": str(root),
        "tech_stack": tech,
        "entry_points": entry_points,
        "git": git_info,
        "index_stats": index_stats,
    }
