"""Bounded ring buffer queue with drop accounting."""

from __future__ import annotations

import collections
import threading
from typing import Callable, Deque, Dict, List, Mapping, Optional


class RingBufferQueue:
    """Thread-safe queue dropping oldest entries when full."""

    def __init__(
        self,
        capacity: int,
        *,
        on_drop: Callable[[Mapping[str, object]], None] | None = None,
    ) -> None:
        """Initialize the queue with a given capacity."""

        if capacity <= 0:
            raise ValueError("Queue capacity must be positive")

        self._capacity = capacity
        self._items: Deque[Mapping[str, object]] = collections.deque()
        self._lock = threading.RLock()
        self._not_empty = threading.Condition(self._lock)
        self._dropped = 0
        self._on_drop = on_drop

    @property
    def dropped(self) -> int:
        """Get the number of dropped items."""
        
        with self._lock:
            return self._dropped

    def size(self) -> int:
        """Get the size of the queue."""

        with self._lock:
            return len(self._items)

    def put(self, item: Mapping[str, object]) -> Optional[Mapping[str, object]]:
        """Add an item to the queue."""

        with self._lock:
            dropped_item: Optional[Mapping[str, object]] = None

            if len(self._items) >= self._capacity:
                dropped_item = self._items.popleft()
                self._dropped += 1
                if self._on_drop is not None:
                    try:
                        self._on_drop(dropped_item)
                    except Exception:  # pragma: no cover - defensive
                        pass

            self._items.append(item)
            self._not_empty.notify()

            return dropped_item

    def drain(self, max_items: int) -> List[Mapping[str, object]]:
        """Drain the queue."""

        with self._lock:
            batch: List[Mapping[str, object]] = []

            while self._items and len(batch) < max_items:
                batch.append(self._items.popleft())

            return batch

    def wait(self, timeout: float) -> bool:
        """Wait for the queue to be not empty with a given timeout."""

        with self._lock:
            if self._items:
                return True

            return self._not_empty.wait(timeout)

    def emit_drop_event(
        self,
        dropped: Mapping[str, object],
        *,
        reason: str = "queue_full",
    ) -> Dict[str, object]:
        """Build metadata describing a drop event."""

        with self._lock:
            drop_count = self._dropped

        return {
            "drop_reason": reason,
            "drop_count": drop_count,
            "dropped_level": dropped.get("level"),
            "dropped_component": dropped.get("component"),
        }


