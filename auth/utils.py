"""Compatibility wrapper exposing authentication utility helpers."""

from app_platform.utils.auth import (
    create_session_fingerprint,
    exponential_backoff,
    generate_session_id,
    hash_password,
    monotonic_ms,
    normalize_utc_timestamp,
    now_ms,
    parse_authorization_header,
    validate_password_strength,
    verify_password,
)

__all__ = [
    "hash_password",
    "verify_password",
    "create_session_fingerprint",
    "generate_session_id",
    "validate_password_strength",
    "normalize_utc_timestamp",
    "parse_authorization_header",
    "now_ms",
    "monotonic_ms",
    "exponential_backoff",
]


