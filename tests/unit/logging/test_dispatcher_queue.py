"""Tests covering dispatcher batching and queue drop behavior."""

from __future__ import annotations

from typing import List

import pytest

from logging_lib.dispatcher import Dispatcher
from logging_lib.metrics import get_metrics
from logging_lib.queue import RingBufferQueue


def _stub_thread_module(monkeypatch):
    """Stub the threading module for testing."""
    
    import logging_lib.dispatcher as dispatcher_module

    class _StubThread:  # pragma: no cover - simple stub
        def __init__(self, *args, **kwargs):
            pass

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            pass

    monkeypatch.setattr(dispatcher_module.threading, "Thread", _StubThread)


def test_dispatcher_flushes_batches(monkeypatch):
    """Dispatcher flush drains queue synchronously and records metrics."""

    import logging_lib.dispatcher as dispatcher_module

    _stub_thread_module(monkeypatch)
    monkeypatch.setattr(dispatcher_module.time, "monotonic", lambda: 0.0)

    emitted: List[dict[str, object]] = []

    class _CollectSink:
        def emit(self, record):
            emitted.append(record)

    queue = RingBufferQueue(8)
    dispatcher = Dispatcher(
        queue,
        [_CollectSink()],
        batch_size=2,
        flush_interval_ms=10,
        flush_timeout_ms=50,
        worker_threads=1,
        retry_initial_ms=1,
        retry_max_ms=1,
    )

    dispatcher.submit({"message": "one"})
    dispatcher.submit({"message": "two"})
    dispatcher.submit({"message": "three"})

    dispatcher.flush()

    assert [record["message"] for record in emitted] == ["one", "two", "three"]

    metrics = get_metrics()
    assert metrics.flush_total == 3
    assert metrics.queue_depth == 0

    dispatcher.stop()


def test_dispatcher_records_retry_when_sink_fails(monkeypatch):
    """Retry metric increments when a sink repeatedly fails."""

    import logging_lib.dispatcher as dispatcher_module

    _stub_thread_module(monkeypatch)

    times = iter([0.0, 0.02])

    def _fake_time():
        return next(times, 0.1)

    monkeypatch.setattr(dispatcher_module.time, "time", _fake_time)
    monkeypatch.setattr(dispatcher_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(dispatcher_module.time, "monotonic", lambda: 0.0)

    failures = []

    class _FlakySink:
        def emit(self, record):
            failures.append(record)
            raise RuntimeError("sink failure")

    queue = RingBufferQueue(2)
    dispatcher = Dispatcher(
        queue,
        [_FlakySink()],
        batch_size=1,
        flush_interval_ms=10,
        flush_timeout_ms=10,
        worker_threads=1,
        retry_initial_ms=1,
        retry_max_ms=1,
    )

    dispatcher.submit({"message": "will-fail"})
    dispatcher.flush()

    metrics = get_metrics()
    assert metrics.retries_total >= 1
    assert failures, "Sink emit should be attempted"

    dispatcher.stop()


def test_logger_manager_emits_drop_notice(logger_manager, memory_sink):
    """Dropping queue items emits a structured notice through the dispatcher."""

    queue = logger_manager._queue  # noqa: SLF001 - validating internals for drop path

    queue.put({"component": "first", "level": "INFO"})
    queue.put({"component": "second", "level": "INFO"})

    logger_manager.dispatcher.flush()

    drop_records = [r for r in memory_sink.records if r["message"] == "log_drop"]
    assert drop_records, "Expected drop notice to be emitted"

    notice = drop_records[-1]
    assert notice["component"] == "logging.queue"
    assert notice["context"]["drop"]["dropped_component"] == "first"

