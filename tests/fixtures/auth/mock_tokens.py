"""Helpers to mint RS256 JWTs for MockAuth0Provider tests."""

from __future__ import annotations

import time
from typing import Dict, Any, Optional

from jose import jwt


def mint_token(
    private_key_pem: str,
    audience: str = "bas-api",
    issuer: str = "https://mock.auth0/",
    subject: str = "user_123",
    expires_in_s: int = 60,
    issued_at_s: Optional[int] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    now = int(issued_at_s if issued_at_s is not None else time.time())
    payload: Dict[str, Any] = {
        "sub": subject,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "exp": now + int(expires_in_s),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


