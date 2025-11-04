"""Tests for logging schema utilities."""

from __future__ import annotations

import pytest

from logging_lib.metrics import get_metrics, reset_metrics
from logging_lib.schema import build_log_record, enforce_payload_limits, validate_record


@pytest.fixture(autouse=True)
def _reset_metrics():
    reset_metrics()
    yield
    reset_metrics()


def test_build_log_record_merges_context_and_fields(logging_settings):
    """Test that build_log_record merges context and fields."""

    record = build_log_record(
        level="INFO",
        message="schema-test",
        settings=logging_settings,
        component="unit",
        context={"tenant": "acme"},
        trace_id="123",
    )

    validate_record(record)
    assert record["component"] == "unit"
    assert record["context"]["tenant"] == "acme"
    assert record["context"]["component"] == "unit"
    assert record["trace_id"] == "123"


def test_build_log_record_defaults_context(logging_settings):
    """Test that build_log_record defaults the context."""

    record = build_log_record(
        level="INFO",
        message="no-context",
        settings=logging_settings,
        component="unit",
    )

    assert record["context"] == {"component": "unit"}


def test_enforce_payload_limits_truncates_large_context(logging_settings):
    """Test that enforce_payload_limits truncates large context."""

    oversized = {"component": "unit", "note": "x" * 2048}
    record = {
        "schema_version": 1,
        "ts": "2024-01-01T00:00:00Z",
        "level": "INFO",
        "service": logging_settings.service,
        "env": logging_settings.env,
        "message": "payload",
        "component": "unit",
        "context": oversized,
    }

    enforce_payload_limits(record, logging_settings.with_overrides(payload_limit_bytes=256))

    metrics = get_metrics()
    assert record.get("context_truncated") is True
    assert metrics.payload_truncations["context"] >= 1


def test_validate_record_raises_for_missing_fields():
    """Test that validate_record raises for missing fields."""
    
    with pytest.raises(ValueError):
        validate_record({"message": "missing fields"})

