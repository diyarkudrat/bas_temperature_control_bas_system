"""Lightweight helpers for signed service-to-service tokens.

The auth service and API communicate with short-lived tokens that loosely
mirror JWT semantics (header.payload.signature) but rely only on the Python
standard library.  Tokens are signed with an HMAC-SHA256 shared secret and
carry the minimal claims we need for issuer/audience validation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, MutableMapping, Optional


_ALG_HEADER = {"alg": "HS256", "typ": "JWT"}
_B64_PAD = "="


class ServiceTokenError(Exception):
    """Base exception for service token helpers."""


class ServiceTokenValidationError(ServiceTokenError):
    """Raised when a service token fails validation."""


@dataclass(slots=True)
class ServiceTokenParams:
    """Common parameters for signing a service token."""

    subject: str
    issuer: str
    audience: str
    secret: str
    ttl_seconds: int = 60
    scope: Optional[str] = None
    extra_claims: Optional[Mapping[str, Any]] = None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip(_B64_PAD)


def _b64url_decode(segment: str) -> bytes:
    padding = (-len(segment)) % 4
    if padding:
        segment += _B64_PAD * padding
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def sign_service_token(params: ServiceTokenParams) -> str:
    """Generate a signed token for service-to-service authorization."""

    if not params.secret:
        raise ServiceTokenError("secret must be provided")
    now = int(time.time())
    payload: MutableMapping[str, Any] = {
        "sub": params.subject,
        "iss": params.issuer,
        "aud": params.audience,
        "iat": now,
        "exp": now + int(params.ttl_seconds),
    }
    if params.scope:
        payload["scope"] = params.scope
    if params.extra_claims:
        for key, value in params.extra_claims.items():
            if key in payload:
                raise ServiceTokenError(f"claim '{key}' cannot be overridden")
            payload[key] = value

    header_segment = _b64url_encode(json.dumps(_ALG_HEADER, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(params.secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_segment = _b64url_encode(signature)
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def verify_service_token(
    token: str,
    *,
    secret: str,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    leeway_seconds: int = 5,
) -> Mapping[str, Any]:
    """Validate a service token and return its claims."""

    if not secret:
        raise ServiceTokenValidationError("secret must be provided")
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
    except ValueError as exc:  # noqa: BLE001
        raise ServiceTokenValidationError("token structure invalid") from exc

    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        signature = _b64url_decode(signature_segment)
    except Exception as exc:  # noqa: BLE001
        raise ServiceTokenValidationError("signature base64 decode failed") from exc

    if not hmac.compare_digest(signature, expected_sig):
        raise ServiceTokenValidationError("signature mismatch")

    try:
        header = json.loads(_b64url_decode(header_segment))
        claims: Mapping[str, Any] = json.loads(_b64url_decode(payload_segment))
    except Exception as exc:  # noqa: BLE001
        raise ServiceTokenValidationError("token payload decode failed") from exc

    if header.get("alg") != "HS256":
        raise ServiceTokenValidationError("unsupported algorithm")

    now = int(time.time())
    exp = int(claims.get("exp", 0))
    if now > (exp + max(0, int(leeway_seconds))):
        raise ServiceTokenValidationError("token expired")

    if audience is not None and claims.get("aud") != audience:
        raise ServiceTokenValidationError("audience mismatch")
    if issuer is not None and claims.get("iss") != issuer:
        raise ServiceTokenValidationError("issuer mismatch")

    return claims


def build_auth_headers(token: str, *, header: str = "Authorization") -> Mapping[str, str]:
    """Construct request headers for passing the service token."""

    if header.lower() == "authorization":
        return {header: f"Bearer {token}"}
    return {header: token}

