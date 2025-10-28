"""Deny-all auth provider (new location)."""

from __future__ import annotations

from typing import Any, Dict, List

from adapters.providers.base import AuthProvider


class DenyAllAuthProvider(AuthProvider):
    def verify_token(self, token: str):  # type: ignore[override]
        raise ValueError("token rejected by deny-all provider")

    def get_user_roles(self, uid: str) -> List[str]:  # type: ignore[override]
        return []

    def healthcheck(self) -> Dict[str, Any]:  # type: ignore[override]
        return {"provider": "DenyAllAuthProvider", "status": "ok"}


