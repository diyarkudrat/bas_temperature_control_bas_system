"""Compatibility wrapper exposing shared schema helpers."""

from app_platform.schemas.base import (  # noqa: F401
    BaseSchema,
    SchemaValidationError,
    ensure_email as _ensure_email,
    ensure_plan as _ensure_plan,
    ensure_tags as _ensure_tags,
    optional_str as _optional_str,
    require_field as _require,
)

__all__ = [
    "BaseSchema",
    "SchemaValidationError",
    "_ensure_email",
    "_ensure_plan",
    "_ensure_tags",
    "_optional_str",
    "_require",
]


