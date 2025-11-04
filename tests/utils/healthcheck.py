"""Helpers for simulating health check dependency states."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Type


@contextmanager
def dependency_probe(mock_probe: Callable[[], None]) -> Iterator[Callable[[], None]]:
    """Provide a dependency probe callable that can be swapped in tests."""

    try:
        yield mock_probe
    finally:
        # Allow tests to assert probe invocation counts or side effects outside the context.
        pass


@dataclass
class Probe:
    """Deterministic dependency probe used to emulate health check behaviour."""

    exception_factory: Callable[[], Exception] | None = None
    failures_remaining: int = 0
    calls: int = 0

    def __call__(self) -> None:
        self.calls += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            exc = self.exception_factory() if self.exception_factory else RuntimeError("probe failure")
            raise exc


def healthy_probe() -> Probe:
    """Return a probe that always succeeds."""

    return Probe()


def failing_probe(
    *,
    failure_count: int = 1,
    exception: Type[Exception] | Callable[[], Exception] | None = None,
) -> Probe:
    """Return a probe that fails ``failure_count`` times before succeeding."""

    if callable(exception):
        factory = exception  # type: ignore[assignment]
    elif exception is None:
        factory = lambda: RuntimeError("probe failure")
    else:
        factory = exception  # type: ignore[assignment]

    return Probe(exception_factory=factory, failures_remaining=failure_count)

