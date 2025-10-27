"""
Auth provider interface for BAS server authentication subsystem.

Defines the minimal contract used by middleware and routes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Mapping


class AuthProvider(ABC):
    """Abstract base class for authentication providers.

    Implementations must be stateless or safely shareable across requests.
    """

    @abstractmethod
    def verify_token(self, token: str) -> Mapping[str, Any]:
        """Verify a JWT and return immutable claims mapping on success.

        Implementations MUST raise a ValueError (or subclass) on invalid tokens
        and MUST NOT perform blocking network I/O in Phase 0.
        """

        raise NotImplementedError

    @abstractmethod
    def get_user_roles(self, uid: str) -> List[str]:
        """Return roles for a given user id.

        In Phase 0, role lookup may be static and local-only.
        """

        raise NotImplementedError

    @abstractmethod
    def healthcheck(self) -> Dict[str, Any]:
        """Return a small health payload for observability."""

        raise NotImplementedError


