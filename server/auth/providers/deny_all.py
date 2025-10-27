"""
Deny-all auth provider.

Used as a safe fallback when configuration is invalid or mocks are
disallowed. Always rejects tokens and reports a stable health payload.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import AuthProvider


class DenyAllAuthProvider(AuthProvider):
    """Fallback provider that denies all tokens."""

    def verify_token(self, token: str):  # type: ignore[override]
        raise ValueError("token rejected by deny-all provider")

    def get_user_roles(self, uid: str) -> List[str]:  # type: ignore[override]
        return []

    def healthcheck(self) -> Dict[str, Any]:  # type: ignore[override]
        return {"provider": "DenyAllAuthProvider", "status": "ok"}


