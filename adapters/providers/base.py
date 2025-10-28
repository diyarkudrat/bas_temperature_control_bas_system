"""
Public AuthProvider interface for adapters package.

This mirrors the legacy interface from server.auth.providers.base and
allows consumers to import from adapters.providers consistently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Mapping


class AuthProvider(ABC):
    """Protocol for an authentication provider."""
    
    @abstractmethod
    def verify_token(self, token: str) -> Mapping[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def get_user_roles(self, uid: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def healthcheck(self) -> Dict[str, Any]:
        raise NotImplementedError


