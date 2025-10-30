"""Configuration utilities for the logging library."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Mapping


_DEFAULT_SERVICE = os.getenv("LOG_SERVICE_NAME", "unknown-service")
_DEFAULT_ENV = os.getenv("LOG_ENV", "local")


@dataclass(frozen=True)
class LoggingSettings:
    """Immutable runtime configuration."""

    service: str = _DEFAULT_SERVICE # The name of the service logging the messages
    env: str = _DEFAULT_ENV # The environment the service is running in
    level: str = os.getenv("LOG_LEVEL", "INFO").upper() # The minimum level of messages to log
    queue_size: int = int(os.getenv("LOG_QUEUE_SIZE", "65536")) # The size of the queue to buffer messages
    batch_size: int = int(os.getenv("LOG_BATCH_SIZE", "128")) # The number of messages to batch before flushing
    flush_interval_ms: int = int(os.getenv("LOG_FLUSH_MS", "200")) # The interval in milliseconds to flush the queue
    flush_timeout_ms: int = int(os.getenv("LOG_FLUSH_TIMEOUT_MS", "5000")) # The timeout in milliseconds to flush the queue
    worker_threads: int = max(1, int(os.getenv("LOG_ASYNC_WORKERS", "2"))) # The number of worker threads to use for the dispatcher
    retry_initial_backoff_ms: int = int(os.getenv("LOG_RETRY_INITIAL_MS", "100")) # The initial backoff in milliseconds to use for the dispatcher
    retry_max_backoff_ms: int = int(os.getenv("LOG_RETRY_MAX_MS", "2000")) # The maximum backoff in milliseconds to use for the dispatcher
    drop_alert_rate: float = float(os.getenv("LOG_DROP_ALERT_RATE", "0.25")) # The rate at which to alert when logs are dropped
    gcl_enabled: bool = os.getenv("LOG_GCL_ENABLED", "1").lower() in {"1", "true", "yes"} # Whether to enable Google Cloud Logging
    gcl_project: str | None = os.getenv("bas-system-project") # The project to use for Google Cloud Logging
    gcl_log_name: str = os.getenv("LOG_GCL_LOG_NAME", "bas-system")  # The name of the log to use for Google Cloud Logging
    sinks: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            filter(None, (os.getenv("LOG_SINKS") or "stdout,gcl").split(","))
        )
    ) # The sinks to use for the logger
    default_context: Mapping[str, Any] = field(default_factory=dict) # The default context to use for the logger

    def with_overrides(self, **kwargs: Any) -> "LoggingSettings":
        """Return a new LoggingSettings with the given overrides."""
        
        return replace(self, **kwargs)


_SETTINGS_LOCK = threading.RLock()
_SETTINGS: LoggingSettings = LoggingSettings()


def load_settings(env: Mapping[str, str] | None = None) -> LoggingSettings:
    """Load settings from environment variables or provided mapping."""

    source = env or os.environ

    sinks_env = source.get("LOG_SINKS")
    if sinks_env:
        sinks = tuple(filter(None, (part.strip() for part in sinks_env.split(","))))
    else:
        sinks = LoggingSettings().sinks

    return LoggingSettings(
        service=source.get("LOG_SERVICE_NAME", _DEFAULT_SERVICE),
        env=source.get("LOG_ENV", _DEFAULT_ENV),
        level=source.get("LOG_LEVEL", "INFO").upper(),
        queue_size=int(source.get("LOG_QUEUE_SIZE", "65536")),
        batch_size=int(source.get("LOG_BATCH_SIZE", "128")),
        flush_interval_ms=int(source.get("LOG_FLUSH_MS", "200")),
        flush_timeout_ms=int(source.get("LOG_FLUSH_TIMEOUT_MS", "5000")),
        worker_threads=max(1, int(source.get("LOG_ASYNC_WORKERS", "2"))),
        retry_initial_backoff_ms=int(source.get("LOG_RETRY_INITIAL_MS", "100")),
        retry_max_backoff_ms=int(source.get("LOG_RETRY_MAX_MS", "2000")),
        drop_alert_rate=float(source.get("LOG_DROP_ALERT_RATE", "0.25")),
        gcl_enabled=source.get("LOG_GCL_ENABLED", "1").lower() in {"1", "true", "yes"},
        gcl_project=source.get("LOG_GCL_PROJECT"),
        gcl_log_name=source.get("LOG_GCL_LOG_NAME", "bas-system"),
        sinks=sinks,
        default_context={},
    )


def configure_settings(
    settings: LoggingSettings | None = None, **overrides: Any
) -> LoggingSettings:
    """Resolve settings and persist them globally."""

    with _SETTINGS_LOCK:
        resolved = settings or load_settings()
        if overrides:
            resolved = resolved.with_overrides(**overrides)
        global _SETTINGS
        _SETTINGS = resolved
        return _SETTINGS


def get_settings() -> LoggingSettings:
    with _SETTINGS_LOCK:
        return _SETTINGS


