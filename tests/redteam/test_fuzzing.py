"""
Tier 6 Hypothesis Property-Based Fuzzing Suite for Protocol Brain.
Fuzzes security invariants and defensive boundaries across:
1. Path confinement engine (confine)
2. Shell operator detection and command capability evaluator
3. Secret redaction engine (redact_secrets)
4. Native Windows notification dispatcher (send_windows_notification)
"""

from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from modules.security.confine import (
    confine,
    has_alternate_data_stream,
    is_dos_device_name,
    is_root_drive,
    is_unc_path,
)
from modules.security.policy import evaluate_command_capability, is_path_under_roots
from modules.security.sanitizer import redact_secrets
from modules.system.notification import MAX_MSG_LEN, MAX_TITLE_LEN, send_windows_notification
from modules.system.shell_runner import FORBIDDEN_OPERATORS, contains_forbidden_operators

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# =====================================================================
# 1. Fuzzing Path Confinement Engine (confine)
# =====================================================================

@given(
    raw_path=st.text(
        alphabet=st.characters(blacklist_categories=("Cs",)),  # avoid standalone surrogates
        max_size=500,
    )
)
@settings(max_examples=100, deadline=None)
def test_fuzz_confine_invariants(raw_path):
    """
    Property: For any arbitrary path string:
    1. confine() must only raise (PermissionError, ValueError, FileNotFoundError, OSError).
    2. If confine() returns a Path:
       - Path MUST be strictly contained inside the trusted roots.
       - Path MUST NOT be a filesystem root drive.
       - Path MUST NOT be a UNC path.
       - Path MUST NOT be an Alternate Data Stream (ADS).
       - Path MUST NOT be a Windows reserved DOS device name.
    """
    # Avoid network NetBIOS / SMB resolution hangs on Windows for random fuzz strings
    norm = raw_path.strip().replace("/", "\\")
    assume(not norm.startswith(r"\\"))
    assume(not norm.startswith(r"\??\UNC"))

    roots = [PROJECT_ROOT]

    try:
        resolved = confine(raw_path, kind="workspace", allow_create=True, trusted_roots=roots)
    except (PermissionError, ValueError, FileNotFoundError, OSError):
        # Expected defensive rejections
        return

    # Invariants on successful confinement
    assert isinstance(resolved, Path)
    assert is_path_under_roots(resolved, roots), f"Confined path escaped roots: {resolved}"
    assert not is_root_drive(resolved), f"Confined path resolved to filesystem root: {resolved}"
    assert not is_unc_path(str(resolved)), f"Confined path is UNC: {resolved}"
    assert not has_alternate_data_stream(str(resolved)), f"Confined path has ADS: {resolved}"
    assert not is_dos_device_name(str(resolved)), f"Confined path is DOS device: {resolved}"


# =====================================================================
# 2. Fuzzing Shell Operator Detection
# =====================================================================

@given(cmd_str=st.text(max_size=300))
@settings(max_examples=150, deadline=None)
def test_fuzz_contains_forbidden_operators(cmd_str):
    """
    Property: contains_forbidden_operators(cmd) must be True if and only if
    at least one character from FORBIDDEN_OPERATORS is present in cmd_str.
    """
    has_operator = any(ch in FORBIDDEN_OPERATORS for ch in cmd_str)
    assert contains_forbidden_operators(cmd_str) == has_operator


# =====================================================================
# 3. Fuzzing Capability Evaluator
# =====================================================================

@given(argv=st.lists(st.text(max_size=100), min_size=0, max_size=10))
@settings(max_examples=150, deadline=None)
def test_fuzz_evaluate_command_capability(argv):
    """
    Property: evaluate_command_capability(argv) must never raise unhandled exceptions
    and must return a valid 3-tuple (is_allowed: bool, req_cap: str, reason: str).
    """
    is_allowed, req_cap, reason = evaluate_command_capability(argv, cwd=PROJECT_ROOT)

    assert isinstance(is_allowed, bool)
    assert isinstance(req_cap, str) and len(req_cap) > 0
    assert isinstance(reason, str)


# =====================================================================
# 4. Fuzzing Native Windows Notification Dispatcher
# =====================================================================

from unittest.mock import patch


@given(
    title=st.text(max_size=500),
    message=st.text(max_size=2000),
)
@settings(max_examples=100, deadline=None)
def test_fuzz_send_windows_notification(title, message):
    """
    Property: send_windows_notification must safely handle any arbitrary string,
    never raise unhandled exceptions, and strictly clamp title and message lengths.
    Mocks subprocess to avoid spawning dozens of real powershell.exe processes.
    """
    captured_calls = []

    def fake_run(cmd, env=None, capture_output=None, timeout=None):
        captured_calls.append({"cmd": cmd, "env": env})
        import subprocess
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

    with patch("modules.system.notification.subprocess.run", side_effect=fake_run):
        res = send_windows_notification(title, message)

    assert isinstance(res, dict)
    assert res.get("success") is True
    assert len(res["title"]) <= MAX_TITLE_LEN
    assert len(res["message"]) <= MAX_MSG_LEN
    assert len(captured_calls) == 1

    # Security check: verify no title/message was injected into command arguments
    cmd_args = captured_calls[0]["cmd"]
    for arg in cmd_args:
        if title and len(title) > 5:
            assert title not in arg, "Sensitive title leaked directly into command args!"
    
    passed_env = captured_calls[0]["env"]
    assert len(passed_env["PB_TITLE"]) <= MAX_TITLE_LEN
    assert len(passed_env["PB_MSG"]) <= MAX_MSG_LEN


# =====================================================================
# 5. Fuzzing Secret Redaction Engine
# =====================================================================

@given(
    prefix=st.sampled_from(["ghp_", "sk-", "AKIA", "CANARY_"]),
    token_body=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", min_size=25, max_size=40),
    surrounding=st.text(max_size=50),
)
@settings(max_examples=100, deadline=None)
def test_fuzz_redact_secrets_invariants(prefix, token_body, surrounding):
    """
    Property: Any sensitive token embedded in text must NEVER survive redact_secrets().
    """
    secret = prefix + token_body
    input_text = f"{surrounding} token={secret} {surrounding}"
    redacted = redact_secrets(input_text)

    assert secret not in redacted, f"Secret leaked through redact_secrets: {secret}"
    assert "[REDACTED_SECRET]" in redacted
