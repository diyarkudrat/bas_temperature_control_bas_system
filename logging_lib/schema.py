"""Structured logging schema utilities."""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any, Dict, Mapping

from .config import LoggingSettings
from .metrics import record_payload_truncation

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
    """Build a structured log record adhering to the canonical schema."""

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

    if context:
        merged = dict(context)
        merged.setdefault("component", component)
        record["context"] = merged
    else:
        record.setdefault("context", {"component": component})

    validate_record(record)
    enforce_payload_limits(record, settings)

    return record


def validate_record(record: Mapping[str, Any]) -> None:
    """Validate a structured log record."""

    missing = REQUIRED_FIELDS.difference(record.keys())

    if missing:
        raise ValueError(f"Log record missing required fields: {sorted(missing)}")

    context = record.get("context", {})
    
    if context is not None and not isinstance(context, Mapping):
        raise TypeError("record context must be a mapping")


def enforce_payload_limits(record: Dict[str, Any], settings: LoggingSettings) -> None:
    """Ensure the record respects payload size and field length limits."""

    _truncate_fields(record, settings)
    limit = settings.payload_limit_bytes

    if _encoded_size(record) <= limit:
        return

    if "context" in record and isinstance(record["context"], Mapping):
        record["context_truncated"] = True
        # Retain only the component to preserve routing signal
        component = record["context"].get("component")  # type: ignore[index]
        record["context"] = {"component": component} if component else {}
        record_payload_truncation("context")

    if _encoded_size(record) <= limit:
        return

    record["payload_truncated"] = True
    record_payload_truncation("payload")

    # Aggressively truncate string fields while keeping critical metadata
    for key, value in list(record.items()):
        if key in {"schema_version", "ts", "level", "service", "env", "component"}:
            continue
        if isinstance(value, str) and len(value) > 128:
            record[key] = value[:128] + settings.redaction.truncate_suffix


def _truncate_fields(record: Dict[str, Any], settings: LoggingSettings) -> None:
    limit = settings.redaction.max_field_length
    suffix = settings.redaction.truncate_suffix

    def _truncate(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if limit == 0 or len(value) <= limit:
            return value
        record_payload_truncation("field")
        return value[:limit] + suffix

    for key, value in list(record.items()):
        if key == "context" and isinstance(value, Mapping):
            record["context"] = {k: _truncate(v) for k, v in value.items()}
        else:
            record[key] = _truncate(value)


def _encoded_size(record: Mapping[str, Any]) -> int:
    return len(json.dumps(record, ensure_ascii=False).encode("utf-8"))


