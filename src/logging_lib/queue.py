"""Thread-safe in-memory queue primitive for log records."""

from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Deque, List, Mapping


class LogQueue:
    """A bounded FIFO queue dropping the oldest record when full."""

    def __init__(self, capacity: int) -> None:
        """Initialize the queue with a given capacity."""

        if capacity <= 0:
            raise ValueError("Queue capacity must be positive")

        self._capacity = capacity
        self._items: Deque[Mapping[str, object]] = deque()
        self._lock = Lock()
        self._dropped = 0

    @property
    def dropped(self) -> int:
        """Return the number of dropped records."""

        return self._dropped

    def put(self, item: Mapping[str, object]) -> None:
        """Add an item to the queue."""

        with self._lock:
            if len(self._items) >= self._capacity:
                self._items.popleft()
                self._dropped += 1
            self._items.append(item)

    def drain(self) -> List[Mapping[str, object]]:
        """Drain the queue and return the items."""
        
        with self._lock:
            items = list(self._items)
            self._items.clear()
            return items


