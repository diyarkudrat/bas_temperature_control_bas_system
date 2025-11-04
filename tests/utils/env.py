"""Environment variable helpers for deterministic unit tests."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Mapping


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

