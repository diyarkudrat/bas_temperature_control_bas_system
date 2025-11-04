"""Utilities for coordinating logging_lib tests."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator

from logging_lib.dispatcher import Dispatcher
from logging_lib.metrics import get_metrics, reset_metrics


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


@contextmanager
def capture_logging_metrics(reset_on_exit: bool = True) -> Iterator[Callable[[], dict[str, Any]]]:
    """Track logging metrics and expose a callable returning the latest snapshot."""

    def snapshot() -> dict[str, Any]:
        return get_metrics().as_dict()

    try:
        yield snapshot
    finally:
        if reset_on_exit:
            reset_logging_metrics()

