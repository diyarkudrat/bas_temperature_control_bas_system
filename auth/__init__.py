"""Compatibility facade for legacy `auth.*` imports.

The testing suite still references modules such as `auth.config` and
`auth.managers` that previously lived under a different repository layout.
This package re-exports the migrated implementations so existing tests and
fixtures can continue to import from `auth.*` without modification.
"""

from app_platform.config.auth import AuthConfig
from application.auth.managers import (
    RateLimitedError,
    RevokedTokenError,
    SessionManager,
    TokenVerificationError,
    UserAuthManager,
    UserManager,
)
from application.auth.services import AuditLogger, RateLimiter
from domains.auth.exceptions import (
    AuthError,
    ConfigurationError,
    PermissionError,
    SessionError,
    UserError,
)
from domains.auth.models import Session, User
from domains.auth.services import RoleService
from app_platform.utils.auth import (
    create_session_fingerprint,
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
    "AuthConfig",
    "AuthError",
    "ConfigurationError",
    "PermissionError",
    "SessionError",
    "UserError",
    "User",
    "Session",
    "UserManager",
    "SessionManager",
    "UserAuthManager",
    "RateLimitedError",
    "TokenVerificationError",
    "RevokedTokenError",
    "AuditLogger",
    "RateLimiter",
    "RoleService",
    "hash_password",
    "verify_password",
    "create_session_fingerprint",
    "generate_session_id",
    "validate_password_strength",
    "normalize_utc_timestamp",
    "now_ms",
    "monotonic_ms",
    "parse_authorization_header",
]


