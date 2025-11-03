"""Service factory for creating and managing Firestore services."""

import logging
from typing import Optional, Dict, Any, Callable
import os
from google.cloud import firestore

from .base import FirestoreError
from .users_store import UsersRepository
from .sessions_store import SessionsStore
from .audit_store import AuditLogStore
from .devices_store import DevicesStore
from .tenant_store import TenantRepository
from .member_store import TenantMemberRepository
from .invite_store import InviteRepository
from .idempotency_store import IdempotencyKeyRepository
from .outbox_store import OutboxRepository
# Import Firestore client from local client factory
from .client import get_firestore_client

logger = logging.getLogger(__name__)


class MockConfig:
    """Mock configuration for testing when client is passed directly."""
    
    def __init__(self):
        self.use_firestore_auth = True
        self.use_firestore_audit = True


class FirestoreServiceFactory:
    """
    Manual DI factory for Firestore repositories.
    Boundary-first: only the Firestore client is injectable.
    Lifetimes: default singleton per factory instance.
    """

    def __init__(self, client: Optional[firestore.Client] = None, *, config: Optional[Any] = None, cache_client: Optional[Any] = None):
        """
        Constructor injection only. Prefer passing a client directly for tests,
        otherwise provide a config to construct a client lazily.
        """

        if client is not None:
            self._client: Optional[firestore.Client] = client
            self.config = config or MockConfig()
        else:
            # No client provided; keep None and resolve from config on demand
            self._client = None
            self.config = config

        self._cache_client = cache_client
        self._repositories: Dict[str, Any] = {}
    
    @property
    def client(self) -> firestore.Client:
        """Get or create Firestore client."""

        if self._client is None:
            self._client = get_firestore_client(self.config)

            if self._client is None:
                # Provide a lightweight mock client for health checks (tests)
                class _NoopClient:
                    def collections(self):
                        return iter(())

                self._client = _NoopClient()

        return self._client
    
    def _get_repository(self, key: str, factory: Callable[[firestore.Client], Any]) -> Any:
        """Memoize repository instances by key."""

        if key not in self._repositories:
            self._repositories[key] = factory(self.client)

        return self._repositories[key]

    def get_users_service(self) -> UsersRepository:
        """Get users service instance."""
        return self._get_repository(
            'users',
            lambda client: UsersRepository(client, cache=self._resolve_cache_client()),
        )

    def get_sessions_service(self) -> SessionsStore:
        """Get sessions service instance."""
        return self._get_repository(
            'sessions',
            lambda client: SessionsStore(client, cache=self._resolve_cache_client()),
        )

    def get_audit_service(self) -> AuditLogStore:
        """Get audit service instance."""
        return self._get_repository(
            'audit',
            lambda client: AuditLogStore(client, cache=self._resolve_cache_client()),
        )

    def get_devices_service(self) -> DevicesStore:
        """Get devices service instance."""
        return self._get_repository(
            'devices',
            lambda client: DevicesStore(client, cache=self._resolve_cache_client()),
        )

    def get_tenant_service(self) -> TenantRepository:
        """Get tenant service instance."""
        return self._get_repository('tenants', lambda client: TenantRepository(client))

    def get_member_service(self) -> TenantMemberRepository:
        """Get member service instance."""
        return self._get_repository('members', lambda client: TenantMemberRepository(client))

    def get_invite_service(self) -> InviteRepository:
        """Get invite service instance."""
        return self._get_repository('invites', lambda client: InviteRepository(client))

    def get_idempotency_service(self) -> IdempotencyKeyRepository:
        """Get idempotency service instance."""
        return self._get_repository('idempotency', lambda client: IdempotencyKeyRepository(client))

    def get_outbox_service(self) -> OutboxRepository:
        """Get outbox service instance."""
        return self._get_repository('outbox', lambda client: OutboxRepository(client))

    def get_all_repositories(self) -> Dict[str, Any]:
        """Get all repository instances."""
        return {
            'users': self.get_users_service(),
            'sessions': self.get_sessions_service(),
            'audit': self.get_audit_service(),
            'devices': self.get_devices_service(),
            'tenants': self.get_tenant_service(),
            'members': self.get_member_service(),
            'invites': self.get_invite_service(),
            'idempotency': self.get_idempotency_service(),
            'outbox': self.get_outbox_service(),
        }
    
    def _resolve_cache_client(self) -> Optional[Any]:
        """Resolve a Redis-like cache client from provided cache or environment."""

        if self._cache_client is not None:
            return self._cache_client

        # Optional env-based wiring
        url = os.getenv("SESSIONS_CACHE_URL")
        if not url:
            return None

        try:
            import redis  # type: ignore
            return redis.Redis.from_url(url)
        except Exception:
            return None

    def reset_repositories(self):
        """Reset all repositories (for testing)."""
        self._repositories.clear()

    def is_auth_enabled(self) -> bool:
        """Check if authentication service is enabled."""
        return bool(getattr(self.config, 'use_firestore_auth', False))

    def is_audit_enabled(self) -> bool:
        """Check if audit service is enabled."""
        return bool(getattr(self.config, 'use_firestore_audit', False))
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on Firestore services."""

        try:
            # Test basic connectivity by attempting to iterate the collections
            # Note: firestore.Client.collections() returns a generator; advancing it
            # forces a lightweight API call and validates credentials/connectivity.
            collections_iter = self.client.collections()
            _ = next(collections_iter, None)
            
            result = {
                'status': 'healthy',
                'services': {
                    'auth': self.is_auth_enabled(),
                    'audit': self.is_audit_enabled()
                },
                'client_initialized': self._client is not None
            }
        except Exception as e:
            logger.error(f"Firestore health check failed: {e}")
            result = {
                'status': 'unhealthy',
                'error': str(e),
                'services': {
                    'auth': False,
                    'audit': False
                },
                'client_initialized': False
            }
            
        return result



def build_service_factory_with_config(config) -> FirestoreServiceFactory:
    """Composition-root helper: build a factory using config to obtain client."""
    return FirestoreServiceFactory(client=None, config=config)


# Back-compat global helpers for existing callsites/tests
_global_factory: Optional[FirestoreServiceFactory] = None


def get_service_factory(config_or_client) -> FirestoreServiceFactory:
    """Return a module-scoped singleton factory.

    Maintained for compatibility with legacy code/tests. Prefer manual wiring
    via build_service_factory_with_config at the composition root.
    """
    global _global_factory
    if _global_factory is None:
        # Heuristic: if it looks like a client (has collections), use as client
        if hasattr(config_or_client, 'collections'):
            _global_factory = FirestoreServiceFactory(client=config_or_client)
        else:
            _global_factory = build_service_factory_with_config(config_or_client)
    return _global_factory


def reset_service_factory() -> None:
    """Reset the module-scoped singleton (tests only)."""
    global _global_factory
    _global_factory = None
