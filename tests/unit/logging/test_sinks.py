"""Tests for logging sinks and observability hooks."""

from __future__ import annotations

import json
from typing import List

import pytest

from logging_lib.metrics import get_metrics


def test_in_memory_sink_records_payload(memory_sink):
    """Ensure the in-memory sink appends deep copies of records."""

    memory_sink.emit({"message": "hello", "nested": {"key": "value"}})

    assert len(memory_sink.records) == 1
    stored = memory_sink.records[0]
    assert stored["message"] == "hello"
    assert stored["nested"] == {"key": "value"}
    assert stored is not memory_sink.records


def test_stdout_sink_emits_json_lines(monkeypatch, logging_settings):
    """Stdout sink should emit JSON serialized payloads."""

    import logging_lib.logger as logger_module

    captured: List[str] = []

    def _fake_print(payload, *, file=None):
        captured.append(payload)

    monkeypatch.setattr("builtins.print", _fake_print)

    stdout_sink = logger_module.StdoutSink(logging_settings)

    stdout_sink.emit({"message": "stdout-test", "component": "unit"})

    assert captured
    parsed = json.loads(captured[0])
    assert parsed["message"] == "stdout-test"
    assert parsed["component"] == "unit"


def test_google_cloud_sink_import_optional(monkeypatch):
    """Ensure optional Google Cloud sink imports fail gracefully."""

    import importlib

    monkeypatch.setitem(importlib.sys.modules, "logging_lib.sinks.gcl_api", None)

    import logging_lib.logger as logger_module

    assert getattr(logger_module, "GoogleCloudLoggingSink", None) is None


def test_drop_notice_increments_metrics(logger_manager, memory_sink):
    """Drop handling increments metrics and emits notice record."""

    queue = logger_manager._queue  # noqa: SLF001 - validating internals for drop path

    for index in range(10):
        queue.put({"component": f"c{index}", "level": "INFO"})

    logger_manager.dispatcher.flush()

    metrics = get_metrics()
    assert metrics.dropped_total >= 1

    drop_records = [r for r in memory_sink.records if r["message"] == "log_drop"]
    assert drop_records, "Expected drop notice to be emitted"

