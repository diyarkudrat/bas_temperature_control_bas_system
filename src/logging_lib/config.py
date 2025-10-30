"""Configuration helpers for the logging library."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Mapping


DEFAULT_SERVICE = os.getenv("LOG_SERVICE_NAME", "unknown-service")
DEFAULT_ENV = os.getenv("LOG_ENV", "local")


@dataclass(frozen=True)
class LoggingSettings:
    """Immutable configuration for the logging library."""

    service: str = DEFAULT_SERVICE
    env: str = DEFAULT_ENV

    level: str = os.getenv("LOG_LEVEL", "INFO").upper()
    queue_size: int = int(os.getenv("LOG_QUEUE_SIZE", "4096"))

    sinks: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            filter(None, (os.getenv("LOG_SINKS") or "stdout").split(","))
        )
    )

    default_context: Mapping[str, Any] = field(default_factory=dict)

    def with_overrides(self, **overrides: Any) -> "LoggingSettings":
        """Return a new instance applying keyword overrides."""

        return replace(self, **overrides)


_SETTINGS_LOCK = threading.RLock()
_SETTINGS: LoggingSettings = LoggingSettings()


def load_settings(env: Mapping[str, str] | None = None) -> LoggingSettings:
    """Load settings from environment variables.

    Parameters
    ----------
    env:
        Optional mapping used instead of :data:`os.environ` for testing.
    """

    source = env or os.environ

    sinks = source.get("LOG_SINKS")
    sink_tuple: tuple[str, ...]

    if sinks:
        sink_tuple = tuple(filter(None, (s.strip() for s in sinks.split(","))))
    else:
        sink_tuple = ("stdout",)

    default_context: Mapping[str, Any] = {}

    return LoggingSettings(
        service=source.get("LOG_SERVICE_NAME", DEFAULT_SERVICE),
        env=source.get("LOG_ENV", DEFAULT_ENV),
        level=source.get("LOG_LEVEL", _SETTINGS.level).upper(),
        queue_size=int(source.get("LOG_QUEUE_SIZE", str(_SETTINGS.queue_size))),
        sinks=sink_tuple,
        default_context=default_context,
    )


def configure_settings(
    settings: LoggingSettings | None = None, **overrides: Any
) -> LoggingSettings:
    """Resolve and store the global settings instance."""

    with _SETTINGS_LOCK:
        resolved = settings or load_settings()

        if overrides:
            resolved = resolved.with_overrides(**overrides)

        global _SETTINGS
        _SETTINGS = resolved
        
        return _SETTINGS


def get_settings() -> LoggingSettings:
    """Return the active settings instance."""

    with _SETTINGS_LOCK:
        return _SETTINGS


