"""
Heuristic Secret Sanitizer and Redaction Module for Protocol Brain.
Performs multi-pattern masking against common token types, secrets, credentials, and connection URIs.
"""

import re
from pathlib import Path
from typing import List

# URL credentials pattern (matches any scheme://user:pass@host)
URL_CREDENTIAL_PATTERN = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\/\s@]+:)([^@\/\s]+)(@)",
    re.IGNORECASE,
)

# Authorization: Bearer <token>
BEARER_TOKEN_PATTERN = re.compile(
    r"(bearer\s+)([A-Za-z0-9\-_.~+/=]+)",
    re.IGNORECASE,
)

# JSON / key-value secrets (e.g. "password": "...", password=...)
KEY_VALUE_SECRET_PATTERN = re.compile(
    r'''((?:["'](?:api[_-]?key|password|secret|auth_token|passwd|private_key|client_secret)["']\s*:\s*|'''
    r'''\b(?:api[_-]?key|password|secret|auth_token|passwd|private_key|client_secret)\s*[:=]\s*)'''
    r'''['"])([^'"]*)(['"])''',
    re.IGNORECASE,
)

# Known token prefixes and private keys
SIMPLE_SECRET_PATTERNS: List[re.Pattern] = [
    # Canary Test Tokens
    re.compile(r"\b(CANARY_[A-Za-z0-9_]+)\b"),
    # GitHub Tokens
    re.compile(r"\b(ghp_[A-Za-z0-9_]{20,})\b"),
    # GHO Tokens
    re.compile(r"\b(gho_[A-Za-z0-9_]{20,})\b"),
    # Fine-grained GitHub PAT
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"),
    # OpenAI & API Keys
    re.compile(r"\b(sk-[A-Za-z0-9-_]{20,})\b"),
    # AWS Access Keys
    re.compile(r"\b(AKIA[0-9A-Za-z]{16,})\b"),
    # PEM Private Keys
    re.compile(r"-----BEGIN [A-Z0-9_\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\s]+PRIVATE KEY-----"),
]

SENSITIVE_KEY_KEYWORDS = {
    "password", "secret", "token", "key", "auth", "credential",
    "private", "cert", "api_key", "apikey", "access_key", "passwd",
}


def is_sensitive_key(key_name: str) -> bool:
    """Check if environment variable or configuration key is sensitive."""
    k_lower = key_name.lower().replace("-", "_")
    return any(w in k_lower for w in SENSITIVE_KEY_KEYWORDS)


def redact_secrets(text: str) -> str:
    """
    Replaces identified sensitive tokens, JSON/env secrets, bearer tokens, and URI credentials with safe placeholders.
    """
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    # 1. URLs with user:pass@
    sanitized = URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED_SECRET]\3", sanitized)

    # 2. Authorization: Bearer <token>
    sanitized = BEARER_TOKEN_PATTERN.sub(r"\1[REDACTED_SECRET]", sanitized)

    # 3. JSON / key-value secrets (e.g. "password": "...", password=...)
    sanitized = KEY_VALUE_SECRET_PATTERN.sub(r'\1[REDACTED_SECRET]\3', sanitized)

    # 4. Simple fixed-prefix tokens & private keys
    for pattern in SIMPLE_SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    # 5. Mask active environment variable values matching sensitive keys
    try:
        import os
        for env_k, env_v in os.environ.items():
            if env_v and len(env_v) >= 8 and is_sensitive_key(env_k):
                sanitized = sanitized.replace(env_v, "[REDACTED_SECRET]")
    except Exception:
        pass

    return sanitized


def format_safe_process_summary(cmdline: List[str], fallback_name: str = "unknown") -> str:
    """
    Returns only executable name + script name, strictly stripping all raw flags and arguments.
    Example: ['python', '-u', 'C:/app/server.py', '--db-pass=123'] -> 'python server.py'
    """
    if not cmdline:
        return fallback_name
    exe = Path(cmdline[0]).name
    script = ""
    for arg in cmdline[1:]:
        arg_clean = arg.strip("\"'")
        p = Path(arg_clean)
        if p.suffix.lower() in (".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".sh", ".ps1") or "/" in arg_clean or "\\" in arg_clean:
            if not arg_clean.startswith("-"):
                script = p.name
                break
    if script:
        return f"{exe} {script}"
    return exe
