"""Unit tests for logging library phase 4 enhancements."""

from __future__ import annotations

import pytest

from logging_lib.config import load_settings
from logging_lib.metrics import get_metrics, reset_metrics
from logging_lib.queue import RingBufferQueue
from logging_lib.redaction import build_registry
from logging_lib.sampling import should_emit
from logging_lib.schema import build_log_record


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    reset_metrics()
    yield
    reset_metrics()


def test_load_settings_includes_redaction_and_sampling() -> None:
    env = {
        "LOG_SAMPLE_RATE_DEFAULT": "0.25",
        "LOG_SAMPLE_RATE_INFO": "0.5",
        "LOG_SAMPLING_STICKY_FIELDS": "request_id,trace_id",
        "LOG_REDACTION_DENYLIST": "password,secret",
        "LOG_REDACTION_TRUNCATE_LENGTH": "32",
        "LOG_REDACTION_TRUNCATE_SUFFIX": "..",
        "LOG_REDACTION_STRICT": "1",
    }

    settings = load_settings(env)

    assert settings.sampling.default_rate == 0.25
    assert settings.sampling.level_overrides["INFO"] == 0.5
    assert settings.sampling.sticky_fields == ("request_id", "trace_id")
    assert settings.redaction.denylist == ("password", "secret")
    assert settings.redaction.max_field_length == 32
    assert settings.redaction.truncate_suffix == ".."
    assert settings.redaction.strict is True


def test_redaction_registry_masks_denylisted_fields() -> None:
    settings = load_settings(
        {
            "LOG_REDACTION_DENYLIST": "password",
            "LOG_REDACTION_CONTEXT_DENYLIST": "token",
        }
    )
    registry = build_registry(settings.redaction)

    record = {
        "level": "INFO",
        "component": "test",
        "password": "supersecret",
        "context": {"token": "abc123", "customer_id": "42"},
    }

    sanitized = registry.apply(record)

    assert sanitized["password"] != "supersecret"
    assert sanitized["context"]["token"] != "abc123"
    assert sanitized["context"]["customer_id"] == "42"


def test_sampling_uses_deterministic_token() -> None:
    env = {
        "LOG_LEVEL": "INFO",
        "LOG_SAMPLE_RATE_INFO": "0.5",
        "LOG_SAMPLE_RATE_DEFAULT": "0.5",
        "LOG_SAMPLING_STICKY_FIELDS": "request_id",
    }
    settings = load_settings(env)

    context = {"request_id": "req-123"}

    outcomes = {should_emit("INFO", settings, context) for _ in range(10)}
    # Deterministic sampling should not vary when sticky field is present
    assert len(outcomes) == 1

    assert should_emit("ERROR", settings, context) is True


def test_queue_drop_emits_metadata() -> None:
    dropped_records = []

    def _on_drop(record):
        dropped_records.append(record)

    queue = RingBufferQueue(1, on_drop=_on_drop)
    queue.put({"component": "c1", "level": "INFO"})
    queue.put({"component": "c2", "level": "INFO"})

    assert len(dropped_records) == 1
    metadata = queue.emit_drop_event(dropped_records[0])
    assert metadata["drop_count"] == 1
    assert metadata["drop_reason"] == "queue_full"
    assert metadata["dropped_component"] == "c1"


def test_schema_enforces_payload_limit() -> None:
    env = {
        "LOG_PAYLOAD_LIMIT_BYTES": "256",
        "LOG_REDACTION_TRUNCATE_LENGTH": "16",
        "LOG_REDACTION_TRUNCATE_SUFFIX": "..",
    }
    settings = load_settings(env)

    long_message = "x" * 1024
    record = build_log_record(
        level="INFO",
        message=long_message,
        settings=settings,
        component="schema-test",
        context={"notes": "y" * 1024},
    )

    assert record["payload_truncated"] is True
    assert record["context_truncated"] is True

    metrics = get_metrics().payload_truncations or {}
    assert metrics["payload"] >= 1

