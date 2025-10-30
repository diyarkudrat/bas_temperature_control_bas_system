"""Dispatcher fan-out for log records."""

from __future__ import annotations

import sys
from threading import RLock
from typing import Iterable, List, Mapping, Protocol

from .queue import LogQueue


class Sink(Protocol):
    def emit(self, record: Mapping[str, object]) -> None:  # pragma: no cover - protocol
        ...


class Dispatcher:
    """Synchronous dispatcher that forwards queued records to sinks."""

    def __init__(self, queue: LogQueue) -> None:
        """Initialize the dispatcher with a given queue."""

        self._queue = queue
        self._sinks: List[Sink] = []
        self._lock = RLock()

    def register_sink(self, sink: Sink) -> None:
        """Register a sink with the dispatcher."""

        with self._lock:
            self._sinks.append(sink)

    def register_sinks(self, sinks: Iterable[Sink]) -> None:
        """Register multiple sinks with the dispatcher."""

        for sink in sinks:
            self.register_sink(sink)

    def submit(self, record: Mapping[str, object]) -> None:
        """Submit a record to the dispatcher."""

        self._queue.put(record)
        self.flush()

    def flush(self) -> None:
        """Flush the queue and send the records to the sinks."""

        batch = self._queue.drain()

        if not batch:
            return

        sinks_snapshot: List[Sink]
        with self._lock:
            sinks_snapshot = list(self._sinks)
            
        for record in batch:
            for sink in sinks_snapshot:
                try:
                    sink.emit(record)
                except Exception:  # pragma: no cover - defensive
                    print("logging_lib dispatcher failed to emit record", file=sys.stderr)


