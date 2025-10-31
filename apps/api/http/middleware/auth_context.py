"""Auth0 JWT context extraction and helpers for request guards.

This module centralizes token parsing, verification, and claim normalization so
route decorators (e.g. ``require_role``) can operate on a stable structure that
is independent from legacy session-based middleware.  The design follows the
updated organization onboarding plan where Auth0-issued access tokens are the
primary credential for API access and contain tenant metadata in custom
namespaced claims.

Key responsibilities:

* Extract Bearer tokens from incoming requests.
* Verify tokens using the configured ``AuthProvider`` (Auth0) with JWKS cache.
* Normalize tenant id, roles, and verification status into ``AuthContext``.
* Provide helper APIs to enforce role hierarchy checks.
* Cache the decoded context on the request to prevent duplicate verification.

The module avoids Flask globals to ease testing; callers pass the request-like
object explicitly (``flask.Request`` or a stub with the same attributes).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Set

from flask import Request

from logging_lib import get_logger as get_structured_logger


logger = get_structured_logger("api.http.middleware.auth_context")


class AuthContextError(Exception):
    """Raised when token extraction or verification fails."""


def _claim_namespace() -> str:
    """Return the Auth0 custom claim namespace with trailing slash."""

    raw = os.getenv("AUTH0_CUSTOM_CLAIM_NAMESPACE", "https://bas.example.com/")
    if not raw.endswith("/"):
        raw += "/"
    return raw


_CUSTOM_NAMESPACE = _claim_namespace()
_TENANT_CLAIM = os.getenv("AUTH0_TENANT_CLAIM", "tenant_id")
_ROLES_CLAIM = os.getenv("AUTH0_ROLES_CLAIM", "roles")
_PERMISSIONS_CLAIM = os.getenv("AUTH0_PERMISSIONS_CLAIM", "permissions")
_SESSION_EPOCH_CLAIM = os.getenv("AUTH0_SESSION_EPOCH_CLAIM", "session_epoch")
_EMAIL_VERIFIED_REQUIRED = os.getenv("AUTH_REQUIRE_EMAIL_VERIFIED", "1").lower() in {"1", "true", "yes"}
_REQUEST_CONTEXT_ATTR = "_auth_context"


def parse_authorization_header(header_value: Optional[str]) -> Optional[str]:
    """Return Bearer token extracted from an Authorization header string."""

    if not header_value or not isinstance(header_value, str):
        return None
    parts = header_value.strip().split()
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


@dataclass(frozen=True)
class AuthContext:
    """Normalized authentication context derived from an Auth0 access token."""

    token: str
    claims: Mapping[str, Any]
    subject: str
    tenant_id: Optional[str]
    roles: frozenset[str]
    scopes: frozenset[str]
    email: Optional[str]
    email_verified: bool
    token_id: Optional[str]
    issued_at: Optional[int]
    expires_at: Optional[int]
    session_epoch: Optional[int]

    def has_role(self, required: str) -> bool:
        """Return True when the context meets or exceeds the required role."""

        hierarchy = {
            "read_only": 1,
            "read-only": 1,
            "operator": 2,
            "admin": 3,
        }

        normalized_required = required.replace("-", "_").lower()
        required_level = hierarchy.get(normalized_required, 0)

        if required_level == 0:
            # Unknown requirement -> fail closed.
            return False

        highest = 0
        for role in self.roles:
            normalized = role.replace("-", "_").lower()
            level = hierarchy.get(normalized)
            if level is None:
                # Accept granular scopes that imply read access when requirement is read-only.
                if normalized_required == "read_only" and (
                    normalized.startswith("read:") or normalized.endswith(":read")
                ):
                    level = 1
                elif normalized in {"devices.write", "devices:write"}:
                    level = 2
                elif normalized in {"admin", "administrator"}:
                    level = 3
                else:
                    continue
            highest = max(highest, level)
            if highest >= required_level:
                return True

        return highest >= required_level

    def require_email_verification(self) -> None:
        if _EMAIL_VERIFIED_REQUIRED and not self.email_verified:
            raise AuthContextError("email not verified")


def _namespaced_claim(claim_name: str, claims: Mapping[str, Any]) -> Any:
    return claims.get(f"{_CUSTOM_NAMESPACE}{claim_name}")


def _extract_roles(claims: Mapping[str, Any]) -> Set[str]:
    roles: Set[str] = set()

    def _add(value: Any) -> None:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                roles.add(stripped)
        elif isinstance(value, Sequence):
            for entry in value:
                _add(entry)
        elif isinstance(value, Mapping):
            for key, enabled in value.items():
                if enabled:
                    _add(key)

    _add(claims.get("roles"))
    _add(claims.get("permissions"))
    _add(claims.get(_PERMISSIONS_CLAIM))
    _add(_namespaced_claim(_ROLES_CLAIM, claims))

    # Namespaced permissions array support
    _add(_namespaced_claim(_PERMISSIONS_CLAIM, claims))

    # Flatten scope string into individual scopes
    scope_value = claims.get("scope")
    if isinstance(scope_value, str):
        for part in scope_value.split():
            _add(part)

    return roles


def _extract_scopes(claims: Mapping[str, Any]) -> Set[str]:
    scopes: Set[str] = set()
    scope_value = claims.get("scope")
    if isinstance(scope_value, str):
        scopes.update(scope_value.split())
    scopes_value = _namespaced_claim("scopes", claims)
    if isinstance(scopes_value, Sequence):
        for item in scopes_value:
            if isinstance(item, str) and item:
                scopes.add(item)
    return scopes


def build_auth_context(
    *,
    token: str,
    provider: Any,
    metrics: Optional[Any] = None,
    require_email_verified: bool = True,
) -> AuthContext:
    """Verify the token and return an ``AuthContext`` instance.

    Args:
        token: Bearer token string from the request.
        provider: Auth provider implementing ``verify_token``.
        metrics: Optional metrics collector (``AuthMetrics``).
        require_email_verified: When true, raise if ``email_verified`` is falsey.

    Raises:
        AuthContextError: on verification failure or missing required claims.
    """

    if provider is None:
        raise AuthContextError("auth provider unavailable")

    start_ms = time.time() * 1000.0
    if metrics is not None:
        try:
            metrics.inc_jwt_attempt()
        except Exception:  # pragma: no cover - metrics errors are non-fatal
            pass

    try:
        claims = provider.verify_token(token)
    except Exception as exc:  # pragma: no cover - propagated as context error
        if metrics is not None:
            try:
                metrics.inc_jwt_failure()
            except Exception:
                pass
        raise AuthContextError(str(exc)) from exc

    if not isinstance(claims, Mapping):
        if metrics is not None:
            try:
                metrics.inc_jwt_failure()
            except Exception:
                pass
        raise AuthContextError("invalid claims")

    if metrics is not None:
        try:
            metrics.observe_jwt_success(time.time() * 1000.0 - start_ms)
        except Exception:
            pass

    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise AuthContextError("missing sub claim")

    tenant_id = _namespaced_claim(_TENANT_CLAIM, claims)
    if tenant_id is None:
        tenant_id = claims.get("tenant_id")
    if isinstance(tenant_id, str):
        tenant_id = tenant_id.strip() or None
    elif tenant_id is not None:
        tenant_id = str(tenant_id)

    roles = frozenset(_extract_roles(claims))
    scopes = frozenset(_extract_scopes(claims))

    email = claims.get("email")
    email_verified = bool(claims.get("email_verified"))
    token_id = claims.get("jti")

    issued_at = None
    exp = None
    try:
        if "iat" in claims:
            issued_at = int(claims["iat"])  # type: ignore[arg-type]
    except Exception:
        issued_at = None
    try:
        if "exp" in claims:
            exp = int(claims["exp"])  # type: ignore[arg-type]
    except Exception:
        exp = None

    session_epoch = None
    try:
        value = _namespaced_claim(_SESSION_EPOCH_CLAIM, claims)
        if value is None:
            value = claims.get("session_epoch")
        if value is not None:
            session_epoch = int(value)
    except Exception:
        session_epoch = None

    context = AuthContext(
        token=token,
        claims=dict(claims),
        subject=subject,
        tenant_id=tenant_id,
        roles=roles,
        scopes=scopes,
        email=str(email) if email else None,
        email_verified=email_verified,
        token_id=str(token_id) if token_id else None,
        issued_at=issued_at,
        expires_at=exp,
        session_epoch=session_epoch,
    )

    if require_email_verified:
        try:
            context.require_email_verification()
        except AuthContextError:
            logger.warning(
                "Token rejected: email not verified",
                extra={"subject": subject, "tenant": tenant_id},
            )
            raise

    return context


def resolve_auth_context(
    request: Request,
    *,
    provider: Any,
    metrics: Optional[Any] = None,
    require_email_verified: bool = True,
) -> AuthContext:
    """Return cached ``AuthContext`` for the request or verify it on demand."""

    existing = getattr(request, _REQUEST_CONTEXT_ATTR, None)
    if isinstance(existing, AuthContext):
        return existing

    token = parse_authorization_header(request.headers.get("Authorization"))
    if not token:
        raise AuthContextError("missing Bearer token")

    context = build_auth_context(
        token=token,
        provider=provider,
        metrics=metrics,
        require_email_verified=require_email_verified,
    )

    try:
        setattr(request, _REQUEST_CONTEXT_ATTR, context)
    except Exception:  # pragma: no cover - attribute assignment best-effort
        pass

    return context


def get_cached_auth_context(request: Request) -> Optional[AuthContext]:
    """Return the cached context if previously resolved within the request."""

    existing = getattr(request, _REQUEST_CONTEXT_ATTR, None)
    if isinstance(existing, AuthContext):
        return existing
    return None


__all__ = [
    "AuthContext",
    "AuthContextError",
    "parse_authorization_header",
    "build_auth_context",
    "resolve_auth_context",
    "get_cached_auth_context",
]


