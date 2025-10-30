"""Sampling helpers."""

from __future__ import annotations

from typing import Mapping

from .config import LoggingSettings

_LEVEL_NUMERIC = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "WARN": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}


def should_emit(level: str, settings: LoggingSettings, context: Mapping[str, object] | None = None) -> bool:
    """Determine if a record should be emitted based on the level and settings."""
    
    threshold = _LEVEL_NUMERIC.get(settings.level.upper(), 20)
    value = _LEVEL_NUMERIC.get(level.upper(), 20)
    return value >= threshold


