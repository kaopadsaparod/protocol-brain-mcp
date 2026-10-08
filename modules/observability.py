"""
Observability and Metrics Module for Protocol Brain.
Provides:
1. Structured Event Logging (with secret redaction).
2. Live Metrics Tracking (calls, latency, token savings, security blocks).
"""

import functools
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .logger import logger
from .security import ToolCategory, get_tool_category, redact_secrets

__all__ = [
    "redact_secrets",
    "MetricsRegistry",
    "metrics",
    "ObservabilityContext",
    "observe_tool",
]


class MetricsRegistry:
    """Thread-safe in-memory metrics collector."""

    def __init__(self):
        self._lock = threading.RLock()
        self.total_tool_calls: int = 0
        self.successful_calls: int = 0
        self.failed_calls: int = 0
        self.security_blocks: int = 0
        self.tokens_saved_estimate: int = 0
        self.call_latencies_ms: Dict[str, List[float]] = {}
        self.tool_usage_counts: Dict[str, int] = {}

    def record_call(
        self,
        tool_name: str,
        duration_ms: float,
        success: bool,
        tokens_saved: int = 0,
        is_security_block: bool = False,
    ):
        with self._lock:
            self.total_tool_calls += 1
            if success:
                self.successful_calls += 1
            else:
                self.failed_calls += 1

            if is_security_block:
                self.security_blocks += 1

            self.tokens_saved_estimate += tokens_saved
            self.tool_usage_counts[tool_name] = self.tool_usage_counts.get(tool_name, 0) + 1

            if tool_name not in self.call_latencies_ms:
                self.call_latencies_ms[tool_name] = []
            self.call_latencies_ms[tool_name].append(round(duration_ms, 2))
            # Keep last 50 entries
            if len(self.call_latencies_ms[tool_name]) > 50:
                self.call_latencies_ms[tool_name].pop(0)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            avg_latencies = {}
            for tool, lats in self.call_latencies_ms.items():
                avg_latencies[tool] = round(sum(lats) / len(lats), 2) if lats else 0.0

            return {
                "total_tool_calls": self.total_tool_calls,
                "successful_calls": self.successful_calls,
                "failed_calls": self.failed_calls,
                "success_rate_percent": round((self.successful_calls / max(1, self.total_tool_calls)) * 100, 1),
                "security_blocks_count": self.security_blocks,
                "estimated_tokens_saved": self.tokens_saved_estimate,
                "tool_usage_counts": dict(self.tool_usage_counts),
                "average_latency_ms": avg_latencies,
            }


metrics = MetricsRegistry()


class ObservabilityContext:
    """Context manager to measure and log structured tool execution events."""

    def __init__(self, tool_name: str, category: str = "UNKNOWN"):
        self.tool_name = tool_name
        self.category = category
        self.request_id = str(uuid.uuid4())[:8]
        self.start_time: float = 0.0
        self.tokens_saved: int = 0
        self.is_security_block: bool = False
        self.is_failure: bool = False

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        success = (exc_type is None) and (not self.is_failure)

        metrics.record_call(
            tool_name=self.tool_name,
            duration_ms=duration_ms,
            success=success,
            tokens_saved=self.tokens_saved,
            is_security_block=self.is_security_block,
        )

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": self.request_id,
            "tool": self.tool_name,
            "category": self.category,
            "duration_ms": round(duration_ms, 2),
            "success": success,
            "is_security_block": self.is_security_block,
            "tokens_saved": self.tokens_saved,
            "error_type": exc_type.__name__ if exc_type else None,
        }
        logger.debug(f"STRUCTURED_EVENT: {json.dumps(event)}")


def observe_tool(tool_name: str, category: Optional[ToolCategory] = None) -> Callable:
    """
    Decorator for MCP tool handlers to automatically capture metrics,
    structured logs, duration, and error classifications.
    """
    cat_val = category.value if category else get_tool_category(tool_name).value

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with ObservabilityContext(tool_name=tool_name, category=cat_val) as ctx:
                try:
                    result = func(*args, **kwargs)
                except Exception:
                    ctx.is_failure = True
                    raise

                if isinstance(result, dict):
                    if result.get("success") is False:
                        ctx.is_failure = True
                        err_text = str(result.get("error", "")).lower()
                        if (
                            "forbidden" in err_text
                            or "denylist" in err_text
                            or "security" in err_text
                            or "capability" in err_text
                            or "blocked" in err_text
                        ):
                            ctx.is_security_block = True

                    # Extract estimated token savings
                    if "saved_tokens" in result:
                        ctx.tokens_saved = int(result["saved_tokens"])
                    elif "token_savings" in result and isinstance(result["token_savings"], dict):
                        ctx.tokens_saved = int(result["token_savings"].get("saved_tokens", 0))

                return result
        return wrapper
    return decorator
