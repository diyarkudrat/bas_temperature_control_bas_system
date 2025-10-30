"""Public API for the structured logging library."""

from __future__ import annotations

from .config import LoggingSettings, configure_settings, get_settings, load_settings
from .logger import configure_manager, get_logger, logger_context, reset_loggers
from .metrics import get_metrics

__all__ = [
    "configure",
    "get_logger",
    "logger_context",
    "LoggingSettings",
    "load_settings",
    "get_settings",
    "get_metrics",
]


def configure(settings: LoggingSettings | None = None, **overrides) -> LoggingSettings:
    """Configure the logging library and start background workers."""

    resolved = configure_settings(settings, **overrides)
    configure_manager(resolved)
    
    return resolved


