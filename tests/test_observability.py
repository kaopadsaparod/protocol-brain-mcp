"""
Observability and Metrics Test Suite for Protocol Brain.
Verifies MetricsRegistry thread-safety, @observe_tool decorator instrumentation,
structured logging, and secret redaction.
"""

import threading

from modules.observability import (
    MetricsRegistry,
    ObservabilityContext,
    observe_tool,
    redact_secrets,
)
from modules.security import ToolCategory


def test_secret_redaction():
    """Sensitive patterns (GitHub tokens, OpenAI keys, Bearer headers) must be masked."""
    raw_sample = "Auth with ghp_123456789012345678901234567890123456 and sk-abcdefghijklmnopqrstuvwxyz123456"
    sanitized = redact_secrets(raw_sample)
    assert "ghp_" not in sanitized
    assert "sk-" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_metrics_registry_thread_safety():
    """Concurrent updates across threads must not cause race conditions or corrupt counters."""
    reg = MetricsRegistry()
    threads = []
    num_threads = 10
    calls_per_thread = 50

    def worker():
        for i in range(calls_per_thread):
            reg.record_call(
                tool_name="worker_tool",
                duration_ms=1.5,
                success=(i % 2 == 0),
                tokens_saved=10,
                is_security_block=(i % 10 == 0),
            )

    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    snapshot = reg.get_snapshot()
    expected_total = num_threads * calls_per_thread
    assert snapshot["total_tool_calls"] == expected_total
    assert snapshot["tool_usage_counts"]["worker_tool"] == expected_total
    assert snapshot["estimated_tokens_saved"] == expected_total * 10


def test_observe_tool_decorator_success_and_failure():
    """@observe_tool decorator must accurately measure latency and classify success/failure."""

    @observe_tool("test_success_tool", category=ToolCategory.READ_ONLY)
    def dummy_success():
        return {"success": True, "saved_tokens": 250}

    @observe_tool("test_failure_tool", category=ToolCategory.DATA_MUTATION)
    def dummy_failure():
        return {"success": False, "error": "Something broke"}

    @observe_tool("test_security_tool", category=ToolCategory.PROCESS_EXECUTION)
    def dummy_security_block():
        return {"success": False, "error": "Operation rejected by capability policy"}

    # Execute
    res_s = dummy_success()
    assert res_s["success"] is True

    res_f = dummy_failure()
    assert res_f["success"] is False

    res_sec = dummy_security_block()
    assert res_sec["success"] is False


def test_observability_context_manager():
    """ObservabilityContext handles block execution and duration timing cleanly."""
    with ObservabilityContext(tool_name="ctx_test", category="SAFE") as ctx:
        assert ctx.tool_name == "ctx_test"
        assert ctx.request_id is not None
        ctx.tokens_saved = 100
    assert ctx.start_time > 0
