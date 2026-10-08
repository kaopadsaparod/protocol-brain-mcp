"""
Heuristic Secret Sanitizer and Redaction Module for Protocol Brain.
Performs multi-pattern masking against common token types, secrets, credentials, and connection URIs.
"""

import re
from typing import List

SECRET_PATTERNS: List[re.Pattern] = [
    # GitHub Tokens
    re.compile(r"\b(ghp_[A-Za-z0-9_]{36,})\b"),
    re.compile(r"\b(gho_[A-Za-z0-9_]{36,})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,})\b"),
    # OpenAI & API Keys
    re.compile(r"\b(sk-[A-Za-z0-9-_]{20,})\b"),
    # AWS Access Keys
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # Bearer Tokens
    re.compile(r"(bearer\s+[A-Za-z0-9-_\.]+)", re.IGNORECASE),
    # Common Key-Value pairs with quotes
    re.compile(r"((api[_-]?key|password|secret|token|auth_token|passwd|private_key)\s*[:=]\s*['\"][^'\"]+['\"])", re.IGNORECASE),
    # Connection string credentials (e.g. postgresql://user:pass@host)
    re.compile(r"((postgres|postgresql|mysql|mongodb|redis):\/\/[^:\/\s]+:)([^@\/\s]+)(@)", re.IGNORECASE),
    # PEM Private Keys
    re.compile(r"-----BEGIN [A-Z0-9_\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\s]+PRIVATE KEY-----"),
]

SENSITIVE_KEY_KEYWORDS = {
    "password", "secret", "token", "key", "auth", "credential",
    "private", "cert", "api_key", "apikey", "access_key", "passwd"
}


def is_sensitive_key(key_name: str) -> bool:
    """Check if environment variable or configuration key is sensitive."""
    k_lower = key_name.lower().replace("-", "_")
    return any(w in k_lower for w in SENSITIVE_KEY_KEYWORDS)


def redact_secrets(text: str) -> str:
    """
    Replaces identified sensitive tokens and patterns with safe placeholders.
    Note: Operates on heuristic regex matching (best-effort masking).
    """
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern in SECRET_PATTERNS:
        # Check if pattern has groups for connection URI
        if "postgres" in pattern.pattern:
            sanitized = pattern.sub(r"\1[REDACTED_SECRET]\4", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    return sanitized
