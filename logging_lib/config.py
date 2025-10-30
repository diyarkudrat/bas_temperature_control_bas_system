"""Configuration utilities for the logging library."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace
from typing import Any, Mapping


def _comma_tuple(value: str | None, *, default: tuple[str, ...]) -> tuple[str, ...]:
    """Convert a comma-separated string to a tuple."""

    if not value:
        return default

    return tuple(filter(None, (part.strip() for part in value.split(","))))


def _bool_env(value: str | None, default: bool) -> bool:
    """Convert a string to a boolean."""

    if value is None:
        return default
        
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class LoggingSettings:
    """Immutable runtime configuration."""

    service: str
    env: str
    level: str
    queue_size: int
    batch_size: int
    flush_interval_ms: int
    flush_timeout_ms: int
    worker_threads: int
    retry_initial_backoff_ms: int
    retry_max_backoff_ms: int
    drop_alert_rate: float
    gcl_enabled: bool
    gcl_project: str | None
    gcl_log_name: str
    sinks: tuple[str, ...]
    default_context: Mapping[str, Any]
    capture_headers: tuple[str, ...]
    exclude_routes: tuple[str, ...]
    request_body_limit: int
    request_id_header: str
    traceparent_header: str

    def with_overrides(self, **kwargs: Any) -> "LoggingSettings":
        return replace(self, **kwargs)


_SETTINGS_LOCK = threading.RLock()
_SETTINGS: LoggingSettings | None = None


def load_settings(env: Mapping[str, str] | None = None) -> LoggingSettings:
    source = env or os.environ
    default_service = source.get("LOG_SERVICE_NAME", "unknown-service")
    default_env = source.get("LOG_ENV", "local")

    sinks = _comma_tuple(source.get("LOG_SINKS"), default=("stdout", "gcl"))
    capture_headers = _comma_tuple(source.get("LOG_CAPTURE_HEADERS"), default=())
    exclude_routes = _comma_tuple(source.get("LOG_EXCLUDE_ROUTES"), default=())

    return LoggingSettings(
        service=default_service,
        env=default_env,
        level=source.get("LOG_LEVEL", "INFO").upper(),
        queue_size=int(source.get("LOG_QUEUE_SIZE", "65536")),
        batch_size=int(source.get("LOG_BATCH_SIZE", "128")),
        flush_interval_ms=int(source.get("LOG_FLUSH_MS", "200")),
        flush_timeout_ms=int(source.get("LOG_FLUSH_TIMEOUT_MS", "5000")),
        worker_threads=max(1, int(source.get("LOG_ASYNC_WORKERS", "2"))),
        retry_initial_backoff_ms=int(source.get("LOG_RETRY_INITIAL_MS", "100")),
        retry_max_backoff_ms=int(source.get("LOG_RETRY_MAX_MS", "2000")),
        drop_alert_rate=float(source.get("LOG_DROP_ALERT_RATE", "0.25")),
        gcl_enabled=_bool_env(source.get("LOG_GCL_ENABLED"), True),
        gcl_project=source.get("LOG_GCL_PROJECT"),
        gcl_log_name=source.get("LOG_GCL_LOG_NAME", "bas-system"),
        sinks=sinks,
        default_context={},
        capture_headers=capture_headers,
        exclude_routes=exclude_routes,
        request_body_limit=int(source.get("LOG_REQUEST_BODY_LIMIT", "0")),
        request_id_header=source.get("LOG_REQUEST_ID_HEADER", "X-Request-Id"),
        traceparent_header=source.get("LOG_TRACE_HEADER", "traceparent"),
    )


def configure_settings(
    settings: LoggingSettings | None = None, **overrides: Any
) -> LoggingSettings:
    with _SETTINGS_LOCK:
        resolved = settings or load_settings()
        if overrides:
            resolved = resolved.with_overrides(**overrides)
        global _SETTINGS
        _SETTINGS = resolved
        return _SETTINGS


def get_settings() -> LoggingSettings:
    with _SETTINGS_LOCK:
        if _SETTINGS is None:
            return configure_settings()
        return _SETTINGS


