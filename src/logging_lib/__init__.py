"""Public API surface for the logging library."""

from __future__ import annotations

from .config import LoggingSettings, configure_settings, get_settings, load_settings
from .logger import configure_manager, get_logger, logger_context, reset_loggers
from .schema import SCHEMA_VERSION

__all__ = [
    "SCHEMA_VERSION",
    "LoggingSettings",
    "configure",
    "get_logger",
    "logger_context",
    "load_settings",
    "get_settings",
]


def configure(settings: LoggingSettings | None = None, **overrides) -> LoggingSettings:
    """Configure the global logging library state.

    Parameters
    ----------
    settings:
        Optional base settings instance. When omitted, settings are loaded from
        environment variables using :func:`load_settings`.
    **overrides:
        Keyword overrides applied on top of the provided or discovered settings.

    Returns
    -------
    LoggingSettings
        The resolved, immutable settings applied to the library.
    """

    resolved = configure_settings(settings, **overrides)
    configure_manager(resolved)
    return resolved


