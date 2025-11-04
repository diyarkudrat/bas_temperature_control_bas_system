"""Tests covering logging configuration and logger manager behavior."""

from __future__ import annotations

import pytest

from logging_lib.logger import LoggerManager


def test_logger_manager_routes_records_to_memory_sink(memory_logger, memory_sink):
    """Test that the logger manager routes records to the in-memory sink."""

    memory_logger.info("log-message", tenant="acme")

    assert len(memory_sink.records) == 1

    record = memory_sink.records[0]
    assert record["message"] == "log-message"
    assert record["component"] == "memory-test"
    assert record["context"]["tenant"] == "acme"


def test_logger_manager_reconfigure_resets_loggers_and_context(
    logger_manager, logging_settings
):
    """Test that the logger manager resets loggers and context when reconfigured."""

    original_logger = logger_manager.get_logger("alpha")
    original_id = id(original_logger)

    updated_settings = logging_settings.with_overrides(
        default_context={"service": "overridden"},
        sinks=("memory",),
    )

    logger_manager.configure(updated_settings)

    refreshed_logger = logger_manager.get_logger("alpha")
    assert id(refreshed_logger) != original_id

    base_context = logger_manager.base_context
    assert base_context == {"service": "overridden"}


def test_logger_manager_queue_recreated_on_reconfigure(logger_manager, logging_settings):
    """Test that the logger manager recreates the queue when reconfigured."""

    initial_queue = logger_manager._queue  # noqa: SLF001 - internal state validation

    resized_settings = logging_settings.with_overrides(queue_size=16)
    logger_manager.configure(resized_settings)

    new_queue = logger_manager._queue  # noqa: SLF001 - internal state validation
    assert new_queue is not initial_queue
    assert getattr(new_queue, "_capacity", None) == 16


def test_logger_manager_lazy_settings_bootstrap(
    logger_manager, monkeypatch, logging_settings
):
    """Test that the logger manager lazily bootstraps settings when accessed."""

    import logging_lib.logger as logger_module

    calls: list[None] = []

    def _fake_get_settings():
        calls.append(None)
        return logging_settings

    monkeypatch.setattr(logger_module, "get_settings", _fake_get_settings)

    logger_manager.reset()
    resolved = logger_manager.settings

    assert calls, "Expected lazy settings lookup to be invoked"
    assert resolved is logging_settings


def test_logger_manager_falls_back_to_stdout(monkeypatch, logging_settings):
    """Test that the logger manager falls back to stdout when no sinks are configured."""
    
    import logging_lib.logger as logger_module

    stdout_calls = []

    class _FakeStdoutSink:
        def __init__(self, settings):
            stdout_calls.append(settings)

        def emit(self, record):
            stdout_calls.append(record)

    def _fail_memory_sink():
        pytest.fail("InMemorySink should not be constructed when no sinks declared")

    class _FakeDispatcher:
        def __init__(self, queue, sinks, **_kwargs):
            self.queue = queue
            self.sinks = list(sinks)

        def submit(self, record):
            for sink in self.sinks:
                sink.emit(record)

        def emit_immediate(self, record):
            for sink in self.sinks:
                sink.emit(record)

        def flush(self):  # pragma: no cover - not exercised
            pass

        def stop(self):  # pragma: no cover - not exercised
            pass

    monkeypatch.setattr(logger_module, "StdoutSink", _FakeStdoutSink)
    monkeypatch.setattr(logger_module, "InMemorySink", lambda: _fail_memory_sink())
    monkeypatch.setattr(logger_module, "Dispatcher", _FakeDispatcher)

    manager = LoggerManager()
    manager.configure(logging_settings.with_overrides(sinks=()))

    assert stdout_calls, "Expected StdoutSink fallback to be instantiated"


