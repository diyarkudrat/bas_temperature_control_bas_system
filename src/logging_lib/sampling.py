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
    """Return ``True`` when the record should be emitted.

    Phase 1 implements a simple severity threshold; future phases can extend
    this to probabilistic sampling and per-route controls.
    """

    threshold = _LEVEL_NUMERIC.get(settings.level.upper(), 20)
    value = _LEVEL_NUMERIC.get(level.upper(), 20)
    
    return value >= threshold


