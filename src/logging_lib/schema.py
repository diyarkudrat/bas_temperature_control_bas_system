"""Structured logging schema helpers."""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Mapping

from .config import LoggingSettings

SCHEMA_VERSION = 1

REQUIRED_FIELDS = {
    "ts",
    "level",
    "service",
    "env",
    "message",
    "schema_version",
}


def _utc_now() -> str:
    return (
        _dt.datetime.now(tz=_dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def build_log_record(
    *,
    level: str,
    message: str,
    settings: LoggingSettings,
    component: str,
    context: Mapping[str, Any] | None = None,
    **fields: Any,
) -> Dict[str, Any]:
    """Create a structured log document adhering to the canonical schema."""

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "ts": _utc_now(),
        "level": level,
        "service": settings.service,
        "env": settings.env,
        "message": message,
        "component": component,
    }

    record.update(fields)

    record.setdefault("context", {})
    if context:
        merged_context = dict(record["context"])
        merged_context.update(context)
        record["context"] = merged_context

    validate_record(record)

    return record


def validate_record(record: Mapping[str, Any]) -> None:
    """Perform lightweight validation of a structured log record."""

    missing = REQUIRED_FIELDS.difference(record.keys())
    
    if missing:
        raise ValueError(f"Log record missing required fields: {sorted(missing)}")
    if not isinstance(record.get("context", {}), Mapping):
        raise TypeError("Log record context must be a mapping")


