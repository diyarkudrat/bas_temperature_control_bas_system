"""Helpers for simulating health check dependency states."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator


@contextmanager
def dependency_probe(mock_probe: Callable[[], None]) -> Iterator[Callable[[], None]]:
    """Provide a dependency probe callable that can be swapped in tests."""

    try:
        yield mock_probe
    finally:
        # Allow tests to assert probe invocation counts or side effects outside the context.
        pass


