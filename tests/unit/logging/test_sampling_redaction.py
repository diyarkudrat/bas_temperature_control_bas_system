"""Tests for sampling and redaction helpers in the logging library."""

from __future__ import annotations

from typing import Dict

import pytest

from logging_lib.config import load_settings
from logging_lib.redaction import build_registry
from logging_lib.sampling import should_emit


def test_sampling_deterministic_with_sticky_fields():
    """Test that sampling is deterministic with sticky fields."""

    settings = load_settings(
        {
            "LOG_LEVEL": "INFO",
            "LOG_SAMPLE_RATE_INFO": "0.5",
            "LOG_SAMPLE_RATE_DEFAULT": "0.5",
            "LOG_SAMPLING_STICKY_FIELDS": "request_id",
        }
    )

    context = {"request_id": "req-123"}

    outcomes = {should_emit("INFO", settings, context) for _ in range(10)}
    assert len(outcomes) == 1

    assert should_emit("ERROR", settings, context) is True


def test_sampling_respects_minimum_level():
    """Test that sampling respects the minimum level."""

    settings = load_settings(
        {
            "LOG_LEVEL": "INFO",
            "LOG_SAMPLING_ENABLED": "1",
            "LOG_SAMPLING_MIN_LEVEL": "ERROR",
        }
    )

    context = {}

    assert should_emit("DEBUG", settings, context) is False
    assert should_emit("INFO", settings, context) is False
    assert should_emit("ERROR", settings, context) is True


def test_sampling_honors_always_emit_levels():
    """Test that sampling honors always emit levels."""

    settings = load_settings(
        {
            "LOG_SAMPLING_ALWAYS_EMIT": "warning,critical",
            "LOG_SAMPLE_RATE_DEFAULT": "0.0",
        }
    )

    assert should_emit("WARNING", settings, {}) is True
    assert should_emit("CRITICAL", settings, {}) is True


def test_redaction_masks_denylisted_fields_and_context():
    """Test that redaction masks denylisted fields and context."""

    settings = load_settings(
        {
            "LOG_REDACTION_DENYLIST": "password",
            "LOG_REDACTION_CONTEXT_DENYLIST": "token",
        }
    )
    registry = build_registry(settings.redaction)

    record = {
        "password": "supersecret",
        "context": {"token": "abc", "customer_id": "42"},
    }

    sanitized = registry.apply(record)

    assert sanitized["password"] != "supersecret"
    assert sanitized["context"]["token"] != "abc"
    assert sanitized["context"]["customer_id"] == "42"


def test_redaction_truncates_long_fields():
    """Test that redaction truncates long fields."""

    settings = load_settings(
        {
            "LOG_REDACTION_TRUNCATE_LENGTH": "4",
            "LOG_REDACTION_TRUNCATE_SUFFIX": "..",
        }
    )
    registry = build_registry(settings.redaction)

    record = {
        "card_number": "1234567890",
        "context": {"note": "abcdef"},
    }

    sanitized = registry.apply(record)

    assert sanitized["card_number"] == "1234.."
    assert sanitized["context"]["note"] == "abcd.."


def test_redaction_allows_custom_module(monkeypatch):
    """Test that redaction allows a custom module."""
    
    settings = load_settings(
        {
            "LOG_REDACTION_MODULE": "custom_redactor",
        }
    )

    registry = build_registry(settings.redaction)

    class _Module:
        @staticmethod
        def build_registry(_settings):
            class _Registry:
                def apply(self, payload: Dict[str, object]):
                    payload = dict(payload)
                    payload["custom"] = True
                    return payload

            return _Registry()

    monkeypatch.setitem(
        registry._builders,  # type: ignore[attr-defined]
        "custom_redactor",
        _Module,
    )

    record = {"value": "data"}
    sanitized = registry.apply(record)
    assert sanitized["custom"] is True

