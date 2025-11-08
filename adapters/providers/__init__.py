"""
Authentication providers package.

Convenience re-exports keep legacy imports working during the adapters
module refactor. Callers may continue to import provider factories from
``adapters.providers`` without chasing the new module layout.
"""

from .auth0 import Auth0Provider
from .deny_all import DenyAllAuthProvider
from .factory import build_auth0_provider
from .mock_auth0 import MockAuth0Provider

__all__ = [
    "Auth0Provider",
    "DenyAllAuthProvider",
    "MockAuth0Provider",
    "build_auth0_provider",
]
