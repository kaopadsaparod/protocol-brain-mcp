"""
Security package for Protocol Brain.
"""

from .confine import (
    add_trusted_workspace,
    confine,
    is_drive_relative,
    is_root_drive,
    is_unc_path,
    remove_trusted_workspace,
)
from .policy import (
    TOOL_CATEGORIES,
    ToolCategory,
    evaluate_command_capability,
    evaluate_tool_capability,
    get_tool_category,
)
from .sanitizer import (
    format_safe_process_summary,
    is_sensitive_key,
    redact_secrets,
)

__all__ = [
    "ToolCategory",
    "TOOL_CATEGORIES",
    "get_tool_category",
    "evaluate_command_capability",
    "evaluate_tool_capability",
    "redact_secrets",
    "is_sensitive_key",
    "format_safe_process_summary",
    "confine",
    "add_trusted_workspace",
    "remove_trusted_workspace",
    "is_unc_path",
    "is_drive_relative",
    "is_root_drive",
]
