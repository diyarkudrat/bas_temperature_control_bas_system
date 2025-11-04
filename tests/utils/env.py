"""Environment variable helpers for deterministic unit tests."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterable, Iterator, Mapping


@contextmanager
def patched_env(overrides: Mapping[str, str | None]) -> Iterator[None]:
    """Temporarily set environment variables for the duration of a block."""

    original: dict[str, str | None] = {}
    for key, value in overrides.items():
        original[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def environment(
    *,
    defaults: Mapping[str, str] | None = None,
    overrides: Mapping[str, str | None] | None = None,
    unset: Iterable[str] | None = None,
) -> Iterator[None]:
    """Apply default and override values while preserving previous state."""

    payload: dict[str, str | None] = {}

    if defaults:
        for key, value in defaults.items():
            if key not in os.environ:
                payload[key] = value

    if overrides:
        payload.update(overrides)

    if unset:
        for key in unset:
            payload[key] = None

    with patched_env(payload):
        yield


def env_flag(name: str, *, default: bool = False) -> bool:
    """Interpret an environment variable as a boolean feature flag."""

    raw = os.getenv(name)
    if raw is None:
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}

