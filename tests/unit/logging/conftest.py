"""Fixtures for logging library unit tests."""

from __future__ import annotations

import os
from typing import Iterable, List, Mapping

import pytest

from logging_lib import get_logger
from logging_lib.config import load_settings
from logging_lib.dispatcher import Sink
from logging_lib.logger import LoggerManager, reset_loggers
from logging_lib.metrics import record_drop, record_flush, set_queue_depth
from logging_lib.queue import RingBufferQueue
from logging_lib.sinks.memory import InMemorySink

from tests.utils.logging import reset_logging_metrics


# Default to lightweight pytest startup for logging-focused suites.
os.environ.setdefault("BAS_DISABLE_PLUGINS", "1")


class _DeterministicDispatcher:
    """Synchronous dispatcher replacement to keep logging tests deterministic."""

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
        self._queue = queue
        self._sinks: List[Sink] = list(sinks)

    def submit(self, record: Mapping[str, object]) -> None:
        """Submit a record to the dispatcher."""

        dropped = self._queue.put(record)
        if dropped is not None:
            level = str(dropped.get("level", "INFO")).upper()
            record_drop(level)
        self.flush()

    def emit_immediate(self, record: Mapping[str, object]) -> None:
        """Emit a record immediately to the sinks."""

        for sink in list(self._sinks):
            sink.emit(record)

    def flush(self) -> None:
        """Flush the dispatcher."""
        
        batch = self._queue.drain(max(1, self._queue.size()))
        if not batch:
            set_queue_depth(self._queue.size())
            return

        for record in batch:
            for sink in list(self._sinks):
                sink.emit(record)

        record_flush(0.0, len(batch))
        set_queue_depth(self._queue.size())

    def stop(self) -> None:
        """Stop the dispatcher."""

        self.flush()

    def register_sink(self, sink: Sink) -> None:
        """Register a sink with the dispatcher."""

        self._sinks.append(sink)

    def register_sinks(self, sinks: Iterable[Sink]) -> None:
        """Register a list of sinks with the dispatcher."""
        
        for sink in sinks:
            self.register_sink(sink)


def pytest_collection_modifyitems(config, items):  # pragma: no cover - Pytest hook
    """Tag every test in this directory with the `logging` marker."""

    for item in items:
        item.add_marker(pytest.mark.logging)


@pytest.fixture(autouse=True)
def _disable_heavy_plugins(monkeypatch, request):
    """Ensure heavyweight pytest plugins stay disabled unless explicitly requested."""

    if request.node.get_closest_marker("logging_use_plugins"):
        return

    monkeypatch.setenv("BAS_DISABLE_PLUGINS", "1")


@pytest.fixture(autouse=True)
def _reset_logging_state():
    """Reset logging globals (manager + metrics) around each test."""

    reset_loggers()
    reset_logging_metrics()
    yield
    reset_logging_metrics()
    reset_loggers()


@pytest.fixture(autouse=True)
def _patch_dispatcher(monkeypatch):
    """Swap the production dispatcher for a deterministic test double."""

    import logging_lib.logger as logger_module

    monkeypatch.setattr(logger_module, "Dispatcher", _DeterministicDispatcher)


@pytest.fixture
def memory_sink_registry(monkeypatch):
    """Capture every in-memory sink instantiated by the logger manager."""

    registry: List[InMemorySink] = []
    original_init = InMemorySink.__init__

    def _tracking_init(self) -> None:  # type: ignore[override]
        original_init(self)
        registry.append(self)

    monkeypatch.setattr(InMemorySink, "__init__", _tracking_init)

    yield registry

    for sink in registry:
        sink.records.clear()


@pytest.fixture
def logging_settings():
    """Provide deterministic logging settings wired to the in-memory sink."""

    return load_settings(
        {
            "LOG_SERVICE_NAME": "logging-unit-tests",
            "LOG_ENV": "test",
            "LOG_LEVEL": "DEBUG",
            "LOG_SINKS": "memory",
            "LOG_GCL_ENABLED": "0",
            "LOG_QUEUE_SIZE": "8",
            "LOG_BATCH_SIZE": "4",
            "LOG_ASYNC_WORKERS": "1",
            "LOG_FLUSH_MS": "0",
            "LOG_FLUSH_TIMEOUT_MS": "50",
            "LOG_RETRY_INITIAL_MS": "1",
            "LOG_RETRY_MAX_MS": "1",
        }
    )


@pytest.fixture
def logger_manager(monkeypatch, logging_settings, memory_sink_registry):
    """Test-scoped logger manager configured with deterministic settings."""

    import logging_lib.config as config_module
    import logging_lib.logger as logger_module

    manager = LoggerManager()

    monkeypatch.setattr(logger_module, "_MANAGER", manager)
    monkeypatch.setattr(config_module, "_SETTINGS", logging_settings, raising=False)

    manager.configure(logging_settings)

    yield manager

    manager.reset()


@pytest.fixture
def dispatcher(logger_manager):
    """Expose the deterministic dispatcher for direct assertions."""

    return logger_manager.dispatcher


@pytest.fixture
def memory_sink(logger_manager, memory_sink_registry):
    """Return the primary in-memory sink registered during configuration."""

    if not memory_sink_registry:
        pytest.fail("Expected an InMemorySink to be registered during configuration")
        
    return memory_sink_registry[0]


@pytest.fixture
def memory_logger(logger_manager):
    """Convenience fixture for producing a logger bound to the in-memory sink."""

    return get_logger("memory-test")

