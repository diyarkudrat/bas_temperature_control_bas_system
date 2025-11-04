"""Utilities for coordinating logging_lib tests."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from logging_lib.dispatcher import Dispatcher
from logging_lib.metrics import reset_metrics


@contextmanager
def synchronous_dispatcher(dispatcher: Dispatcher) -> Iterator[Dispatcher]:
    """Force a dispatcher to flush synchronously within the context."""

    dispatcher.flush(block=True)
    try:
        yield dispatcher
    finally:
        dispatcher.flush(block=True)


def reset_logging_metrics() -> None:
    """Reset logging metrics between tests."""

    reset_metrics()

