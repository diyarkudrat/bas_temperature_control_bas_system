"""Compatibility wrapper for authentication exception types."""

from domains.auth.exceptions import (
    AuthError,
    ConfigurationError,
    PermissionError,
    SessionError,
    UserError,
)

__all__ = [
    "AuthError",
    "ConfigurationError",
    "PermissionError",
    "SessionError",
    "UserError",
]


