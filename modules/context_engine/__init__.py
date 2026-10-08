"""
Protocol Brain Context Engine & Terminal AI Intelligence Package.
High-speed, token-frugal context synthesis for AI coding agents.
"""

from .engine import prepare_context
from .error_tracer import trace_error
from .impact_analyzer import find_impact, find_relevant_tests, git_context
from .project_inspector import inspect_project
from .runtime_inspector import inspect_local_services, inspect_runtime

__all__ = [
    "prepare_context",
    "inspect_project",
    "trace_error",
    "find_impact",
    "find_relevant_tests",
    "git_context",
    "inspect_runtime",
    "inspect_local_services",
]
