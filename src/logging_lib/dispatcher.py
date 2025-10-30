"""Asynchronous dispatcher for log records."""

from __future__ import annotations

import sys
import threading
import time
from typing import Iterable, List, Mapping, Protocol

from .metrics import record_flush, record_retry, record_drop, set_queue_depth
from .queue import RingBufferQueue


class Sink(Protocol):
    """A sink for log records."""

    def emit(self, record: Mapping[str, object]) -> None:  # pragma: no cover - protocol
        ...


class Dispatcher:
    """Background dispatcher that drains the queue and fans out to sinks."""

    def __init__(
        self,
        queue: RingBufferQueue,
        sinks: Iterable[Sink],
        *,
        batch_size: int,
        flush_interval_ms: int,
        flush_timeout_ms: int,
        worker_threads: int,
        retry_initial_ms: int,
        retry_max_ms: int,
    ) -> None:
        """Initialize the dispatcher with a given queue, sinks, and configuration."""

        self._queue = queue # The queue to drain
        self._sinks: List[Sink] = list(sinks) # The sinks to send the records to
        self._batch_size = max(1, batch_size) # The batch size to flush
        self._flush_interval = flush_interval_ms / 1000.0 # The flush interval in seconds
        self._flush_timeout = flush_timeout_ms / 1000.0 # The flush timeout in seconds
        self._initial_backoff = retry_initial_ms / 1000.0 # The initial backoff in seconds
        self._max_backoff = max(self._initial_backoff, retry_max_ms / 1000.0) # The maximum backoff in seconds
        self._stop_event = threading.Event() # The event to stop the dispatcher
        self._threads: List[threading.Thread] = [] # The threads to run the dispatcher
        self._lock = threading.RLock() # The lock for the sinks

        for index in range(max(1, worker_threads)):
            thread = threading.Thread(
                target=self._worker,
                name=f"logging-dispatcher-{index}",
                daemon=True,
            )

            thread.start()

            self._threads.append(thread)

    def register_sink(self, sink: Sink) -> None:
        """Register a sink with the dispatcher."""

        with self._lock:
            self._sinks.append(sink)

    def register_sinks(self, sinks: Iterable[Sink]) -> None:
        """Register a list of sinks with the dispatcher."""

        for sink in sinks:
            self.register_sink(sink)

    def submit(self, record: Mapping[str, object]) -> None:
        """Submit a record to the dispatcher."""

        dropped = self._queue.put(record)

        if dropped is not None:
            level = str(dropped.get("level", "INFO"))

            record_drop(level)

    def flush(self) -> None:
        deadline = time.time() + self._flush_timeout

        while time.monotonic() < deadline:
            batch = self._queue.drain(self._batch_size)

            if not batch:
                break

            self._emit_batch(batch)

    def stop(self) -> None:
        """Stop the dispatcher."""

        self._stop_event.set()

        for thread in self._threads:
            thread.join(timeout=1.0)

    # --------------------- internal helpers ---------------------
    def _worker(self) -> None:
        """Run the dispatcher worker."""

        while not self._stop_event.is_set():
            has_items = self._queue.wait(self._flush_interval)

            if not has_items and not self._queue.size():
                continue
            
            batch = self._queue.drain(self._batch_size)
            if not batch:
                continue

            self._emit_batch(batch)

    def _emit_batch(self, batch: List[Mapping[str, object]]) -> None:
        """Emit a batch of records to the sinks."""

        start = time.perf_counter()

        sinks_snapshot = self._snapshot_sinks()

        for record in batch:
            for sink in sinks_snapshot:
                self._emit_with_retry(sink, record)

        duration_ms = (time.perf_counter() - start) * 1000.0

        record_flush(duration_ms, len(batch))

        set_queue_depth(self._queue.size())

    def _snapshot_sinks(self) -> List[Sink]:
        """Snapshot the sinks."""

        with self._lock:
            return list(self._sinks)

    def _emit_with_retry(self, sink: Sink, record: Mapping[str, object]) -> None:
        """Emit a record to a sink with a given retry policy."""

        backoff = self._initial_backoff
        deadline = time.time() + self._flush_timeout

        while True:
            try:
                sink.emit(record)

                return
            except Exception:  # pragma: no cover - defensive
                record_retry()

                print(
                    "logging_lib dispatcher failed to emit record", file=sys.stderr
                )

                if time.time() + backoff > deadline:
                    return
                    
                time.sleep(backoff)
                backoff = min(backoff * 2, self._max_backoff)


