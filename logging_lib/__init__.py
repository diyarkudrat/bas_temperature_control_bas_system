"""Public API for the structured logging library."""

from __future__ import annotations

from .config import LoggingSettings, configure_settings, get_settings, load_settings
from .context import bind_context, capture_context, run_with_context
from .logger import (
    clear_context,
    configure_manager,
    get_context,
    get_logger,
    logger_context,
    pop_context,
    push_context,
    reset_loggers,
)
from .metrics import get_metrics

__all__ = [
    "configure",
    "get_logger",
    "logger_context",
    "LoggingSettings",
    "load_settings",
    "get_settings",
    "get_metrics",
    "push_context",
    "pop_context",
    "get_context",
    "clear_context",
    "capture_context",
    "bind_context",
    "run_with_context",
]


def configure(settings: LoggingSettings | None = None, **overrides) -> LoggingSettings:
    """Configure the logging library and start background workers."""

    resolved = configure_settings(settings, **overrides)
    configure_manager(resolved)
    
    return resolved


