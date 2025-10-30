"""Context propagation helpers for background tasks."""

from __future__ import annotations

from contextvars import Token
from typing import Any, Callable, Mapping

from .logger import get_context, pop_context, push_context


Context = Mapping[str, Any]


def capture_context(extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a shallow copy of the current logging context."""

    payload = dict(get_context())
    if extra:
        payload.update(extra)
    return payload


def bind_context(**context: Any) -> Token:
    """Merge the supplied context into the current logging scope and return a token."""

    return push_context(**context)


def run_with_context(
    context: Context,
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Execute ``func`` with the provided logging context bound."""

    token = push_context(**context)
    try:
        return func(*args, **kwargs)
    finally:
        pop_context(token)

