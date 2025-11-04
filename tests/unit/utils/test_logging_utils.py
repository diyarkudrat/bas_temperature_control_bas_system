"""Unit tests for logging utility helpers."""

from __future__ import annotations

from logging_lib.metrics import record_drop

from tests.utils.logging import capture_logging_metrics


def test_capture_logging_metrics_reports_runtime_changes():
    with capture_logging_metrics() as snapshot:
        record_drop("INFO")
        metrics = snapshot()

    assert metrics["dropped_total"] == 1
    assert metrics["dropped_levels"]["INFO"] == 1

