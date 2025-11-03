"""Configuration utilities for the logging library."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping, MutableMapping


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


def _int_env(value: str | None, default: int) -> int:
    if value is None:
        return default

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float_env(value: str | None, default: float) -> float:
    if value is None:
        return default

    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default

    return max(0.0, min(1.0, parsed))


def _upper_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(value.upper() for value in values)


@dataclass(frozen=True)
class RedactionSettings:
    """Configuration for deterministic field redaction."""

    enabled: bool
    denylist: tuple[str, ...]
    allowlist: tuple[str, ...]
    context_denylist: tuple[str, ...]
    truncate_fields: tuple[str, ...]
    max_field_length: int
    truncate_suffix: str
    hash_salt: str
    custom_module: str | None
    strict: bool


@dataclass(frozen=True)
class SamplingSettings:
    """Configuration for probabilistic log sampling."""

    enabled: bool
    default_rate: float
    level_overrides: Mapping[str, float]
    sticky_fields: tuple[str, ...]
    min_level: str
    always_emit_levels: tuple[str, ...]


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
    payload_limit_bytes: int
    redaction: RedactionSettings
    sampling: SamplingSettings

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

    redaction_settings = RedactionSettings(
        enabled=_bool_env(source.get("LOG_REDACTION_ENABLED"), True),
        denylist=_comma_tuple(source.get("LOG_REDACTION_DENYLIST"), default=()),
        allowlist=_comma_tuple(source.get("LOG_REDACTION_ALLOWLIST"), default=()),
        context_denylist=_comma_tuple(
            source.get("LOG_REDACTION_CONTEXT_DENYLIST"), default=("password", "token")
        ),
        truncate_fields=_comma_tuple(
            source.get("LOG_REDACTION_TRUNCATE_FIELDS"), default=("request_body",)
        ),
        max_field_length=_int_env(source.get("LOG_REDACTION_TRUNCATE_LENGTH"), 1024),
        truncate_suffix=source.get("LOG_REDACTION_TRUNCATE_SUFFIX", "..."),
        hash_salt=source.get("LOG_REDACTION_HASH_SALT", ""),
        custom_module=source.get("LOG_REDACTION_MODULE"),
        strict=_bool_env(source.get("LOG_REDACTION_STRICT"), False),
    )

    default_sampling_rate = _float_env(
        source.get("LOG_SAMPLE_RATE_DEFAULT"), 1.0
    )
    level_overrides: MutableMapping[str, float] = {
        level: _float_env(
            source.get(f"LOG_SAMPLE_RATE_{level}"), default_sampling_rate
        )
        for level in ("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    }

    sampling_settings = SamplingSettings(
        enabled=_bool_env(source.get("LOG_SAMPLING_ENABLED"), True),
        default_rate=default_sampling_rate,
        level_overrides=MappingProxyType({k: v for k, v in level_overrides.items()}),
        sticky_fields=_comma_tuple(
            source.get("LOG_SAMPLING_STICKY_FIELDS"), default=("trace_id", "request_id")
        ),
        min_level=source.get("LOG_SAMPLING_MIN_LEVEL", source.get("LOG_LEVEL", "INFO")).upper(),
        always_emit_levels=_upper_tuple(
            _comma_tuple(
                source.get("LOG_SAMPLING_ALWAYS_EMIT"), default=("ERROR", "CRITICAL")
            )
        ),
    )

    return LoggingSettings(
        service=default_service,
        env=default_env,
        level=source.get("LOG_LEVEL", "INFO").upper(),
        queue_size=_int_env(source.get("LOG_QUEUE_SIZE"), 65536),
        batch_size=_int_env(source.get("LOG_BATCH_SIZE"), 128),
        flush_interval_ms=_int_env(source.get("LOG_FLUSH_MS"), 200),
        flush_timeout_ms=_int_env(source.get("LOG_FLUSH_TIMEOUT_MS"), 5000),
        worker_threads=max(1, _int_env(source.get("LOG_ASYNC_WORKERS"), 2)),
        retry_initial_backoff_ms=_int_env(source.get("LOG_RETRY_INITIAL_MS"), 100),
        retry_max_backoff_ms=_int_env(source.get("LOG_RETRY_MAX_MS"), 2000),
        drop_alert_rate=float(source.get("LOG_DROP_ALERT_RATE", "0.25")),
        gcl_enabled=_bool_env(source.get("LOG_GCL_ENABLED"), True),
        gcl_project=source.get("LOG_GCL_PROJECT"),
        gcl_log_name=source.get("LOG_GCL_LOG_NAME", "bas-system"),
        sinks=sinks,
        default_context={},
        capture_headers=capture_headers,
        exclude_routes=exclude_routes,
        request_body_limit=_int_env(source.get("LOG_REQUEST_BODY_LIMIT"), 0),
        request_id_header=source.get("LOG_REQUEST_ID_HEADER", "X-Request-Id"),
        traceparent_header=source.get("LOG_TRACE_HEADER", "traceparent"),
        payload_limit_bytes=_int_env(source.get("LOG_PAYLOAD_LIMIT_BYTES"), 16_384),
        redaction=redaction_settings,
        sampling=sampling_settings,
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


