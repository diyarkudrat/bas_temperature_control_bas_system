"""Deny-all auth provider. Used for fallback when Auth0 is unavailable."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from adapters.providers.base import AuthProvider


class DenyAllAuthProvider(AuthProvider):
    def verify_token(self, token: str) -> Mapping[str, Any]:
        raise ValueError("token rejected by deny-all provider")

    def get_user_roles(self, uid: str) -> List[str]:
        return []

    def healthcheck(self) -> Dict[str, Any]:
        return {"provider": "DenyAllAuthProvider", "status": "ok"}