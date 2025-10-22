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
		self._data: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
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
			ts, value = item
			if now - ts > self._ttl_s:
				self._data.pop(key, None)
				return None
			self._data.move_to_end(key)
			return value

	def set(self, key: str, value: Any) -> None:
		with self._lock:
			self._data[key] = (time.monotonic(), value)
			self._data.move_to_end(key)
			while len(self._data) > self._capacity:
				self._data.popitem(last=False)

	def delete(self, key: str) -> None:
		with self._lock:
			self._data.pop(key, None)

	def keys(self) -> Iterable[str]:
		with self._lock:
			return list(self._data.keys())


