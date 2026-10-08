"""
Protocol Brain Context Engine & Terminal AI Intelligence Package.
High-speed, token-frugal context synthesis, call graphs, diff intelligence,
and container stack awareness for AI coding agents.
"""

from .call_graph import get_call_graph
from .codebase_qa import ask_codebase
from .config_inspector import inspect_config_usage
from .diff_intelligence import find_changed_dependencies, suggest_tests_for_change
from .docker_inspector import inspect_docker_stack, why_service_unhealthy
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
    "get_call_graph",
    "suggest_tests_for_change",
    "find_changed_dependencies",
    "ask_codebase",
    "inspect_docker_stack",
    "why_service_unhealthy",
    "inspect_config_usage",
]
