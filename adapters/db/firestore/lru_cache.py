"""Extensible, thread-safe LRU cache with TTL for hot-path lookups."""
from __future__ import annotations

import time
import threading
from collections import OrderedDict
from typing import Any, Optional, Tuple, Iterable


class LRUCache:
    """Thread-safe LRU with TTL and minimal API.

    - get(key) -> Optional[Any]
    - set(key, value) -> None
    - configure(capacity, ttl_s) -> None
    - keys() -> Iterable[str]
    """

    def __init__(self, capacity: int = 128, ttl_s: int = 5) -> None:
        self._capacity = max(1, capacity)
        self._ttl_s = max(1, ttl_s)
        # Store triples: (timestamp, value, version)
        self._data: OrderedDict[str, Tuple[float, Any, Optional[int]]] = OrderedDict()
        self._lock = threading.RLock()

    def configure(self, *, capacity: Optional[int] = None, ttl_s: Optional[int] = None) -> None:
        with self._lock:
            if capacity is not None:
                self._capacity = max(1, capacity)
            if ttl_s is not None:
                self._ttl_s = max(1, ttl_s)

    def get(self, key: str) -> Optional[Any]:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            ts, value, _ver = item
            if now - ts > self._ttl_s:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def get_versioned(self, key: str) -> Optional[Tuple[Any, Optional[int]]]:
        """Get value and version atomically; respects TTL and LRU semantics."""
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            ts, value, ver = item
            if now - ts > self._ttl_s:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value, ver

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value, None)
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)

    def set_versioned(self, key: str, value: Any, version: Optional[int]) -> None:
        """Set value with version under lock; enforces capacity policy."""
        with self._lock:
            self._data[key] = (time.monotonic(), value, version)
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def bust_if_version_mismatch(self, key: str, new_version: Optional[int]) -> bool:
        """Atomically bust entry if stored version differs from new_version.

        Returns True if an entry existed and was removed due to mismatch.
        """
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return False
            _ts, _val, ver = entry
            if ver != new_version:
                self._data.pop(key, None)
                return True
            return False

    def keys(self) -> Iterable[str]:
        with self._lock:
            return list(self._data.keys())
