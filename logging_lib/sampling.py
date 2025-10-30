"""Sampling helpers."""

from __future__ import annotations

import hashlib
import random
from typing import Iterable, Mapping

from .config import LoggingSettings
from .metrics import record_sampling_decision

_LEVEL_NUMERIC = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "WARN": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}


def should_emit(
    level: str,
    settings: LoggingSettings,
    context: Mapping[str, object] | None = None,
) -> bool:
    """Determine if a record should be emitted for a given log level."""

    numeric_level = _LEVEL_NUMERIC.get(level.upper(), 20)
    configured_threshold = _LEVEL_NUMERIC.get(settings.level.upper(), 20)

    sampling = settings.sampling

    if numeric_level < configured_threshold:
        record_sampling_decision(level, False)
        return False

    if not sampling.enabled:
        record_sampling_decision(level, True)
        return True

    upper_level = level.upper()

    if upper_level in sampling.always_emit_levels:
        record_sampling_decision(level, True)
        return True

    min_level_threshold = _LEVEL_NUMERIC.get(sampling.min_level.upper(), configured_threshold)
    if numeric_level < min_level_threshold:
        record_sampling_decision(level, False)
        return False

    rate = sampling.level_overrides.get(upper_level, sampling.default_rate)
    rate = max(0.0, min(1.0, rate))

    if rate >= 1.0:
        record_sampling_decision(level, True)
        return True

    if rate <= 0.0:
        record_sampling_decision(level, False)
        return False

    probability = _deterministic_probability(upper_level, sampling.sticky_fields, context)
    decision = probability < rate
    record_sampling_decision(level, decision)
    return decision


def _deterministic_probability(
    level: str, sticky_fields: Iterable[str], context: Mapping[str, object] | None
) -> float:
    token = _resolve_sampling_token(level, sticky_fields, context)
    if token is None:
        return random.random()

    digest = hashlib.blake2s(str(token).encode("utf-8", "ignore"), digest_size=8).digest()
    value = int.from_bytes(digest, byteorder="big")
    return value / float(2 ** (8 * len(digest)))


def _resolve_sampling_token(
    level: str, sticky_fields: Iterable[str], context: Mapping[str, object] | None
) -> str | None:
    if not context:
        return level

    for field in sticky_fields:
        try:
            if hasattr(context, "get"):
                candidate = context.get(field)
            else:
                candidate = dict(context).get(field)
        except Exception:
            candidate = None

        if candidate is not None:
            return f"{field}:{candidate}"

    return level


