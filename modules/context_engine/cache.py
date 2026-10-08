"""
3-Tier Multi-Level Cache for Protocol Brain Context Engine.
L1: Request-Scoped Context Cache
L2: Process In-Memory LRU Cache (Thread-Safe)
L3: SQLite Persistent Relational Index
"""

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional


class RequestCache:
    """L1: Request-scoped cache that lives only during a single tool invocation chain."""

    def __init__(self):
        self._data: Dict[str, Any] = {}

    def get(self, key: str) -> Optional[Any]:
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def clear(self) -> None:
        self._data.clear()


class MemoryLRUCache:
    """L2: Thread-safe in-memory LRU cache with TTL support."""

    def __init__(self, maxsize: int = 256, default_ttl_sec: float = 60.0):
        self.maxsize = maxsize
        self.default_ttl = default_ttl_sec
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            val, expires_at = self._cache[key]
            if time.time() > expires_at:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return val

    def set(self, key: str, value: Any, ttl_sec: Optional[float] = None) -> None:
        with self._lock:
            ttl = ttl_sec if ttl_sec is not None else self.default_ttl
            expires_at = time.time() + ttl
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, expires_at)
            if len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def get_or_compute(self, key: str, factory: Callable[[], Any], ttl_sec: Optional[float] = None) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        val = factory()
        if val is not None:
            self.set(key, val, ttl_sec)
        return val

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Global cache singletons
memory_cache = MemoryLRUCache()
request_cache = RequestCache()
