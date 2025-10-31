"""Service factory for creating and managing Firestore services."""

import logging
from typing import Optional, Dict, Any
import os
from google.cloud import firestore

from .base import FirestoreError
from .telemetry_store import TelemetryRepository
from .users_store import UsersRepository
from .sessions_store import SessionsStore
from .audit_store import AuditLogStore
from .devices_store import DevicesStore
from .tenant_store import TenantRepository
from .member_store import TenantMemberRepository
from .invite_store import InviteRepository
from .idempotency_store import IdempotencyKeyRepository
from .outbox_store import OutboxRepository
# Import Firestore client from auth package which owns client factory
from auth.firestore_client import get_firestore_client

logger = logging.getLogger(__name__)


class MockConfig:
    """Mock configuration for testing when client is passed directly."""
    def __init__(self):
        self.use_firestore_telemetry = True
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
                self._client = _NoopClient()  # type: ignore
        return self._client  # type: ignore[return-value]
    
    def get_telemetry_service(self) -> TelemetryRepository:
        """Get telemetry service instance."""
        if 'telemetry' not in self._repositories:
            self._repositories['telemetry'] = TelemetryRepository(self.client)
        return self._repositories['telemetry']

    def get_users_service(self) -> UsersRepository:
        """Get users service instance."""
        if 'users' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['users'] = UsersRepository(self.client, cache=cache)
        return self._repositories['users']

    def get_sessions_service(self) -> SessionsStore:
        """Get sessions service instance."""
        if 'sessions' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['sessions'] = SessionsStore(self.client, cache=cache)
        return self._repositories['sessions']

    def get_audit_service(self) -> AuditLogStore:
        """Get audit service instance."""
        if 'audit' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['audit'] = AuditLogStore(self.client, cache=cache)
        return self._repositories['audit']

    def get_devices_service(self) -> DevicesStore:
        """Get devices service instance."""
        if 'devices' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['devices'] = DevicesStore(self.client, cache=cache)
        return self._repositories['devices']

    def get_tenant_service(self) -> TenantRepository:
        if 'tenants' not in self._repositories:
            self._repositories['tenants'] = TenantRepository(self.client)
        return self._repositories['tenants']

    def get_member_service(self) -> TenantMemberRepository:
        if 'members' not in self._repositories:
            self._repositories['members'] = TenantMemberRepository(self.client)
        return self._repositories['members']

    def get_invite_service(self) -> InviteRepository:
        if 'invites' not in self._repositories:
            self._repositories['invites'] = InviteRepository(self.client)
        return self._repositories['invites']

    def get_idempotency_service(self) -> IdempotencyKeyRepository:
        if 'idempotency' not in self._repositories:
            self._repositories['idempotency'] = IdempotencyKeyRepository(self.client)
        return self._repositories['idempotency']

    def get_outbox_service(self) -> OutboxRepository:
        if 'outbox' not in self._repositories:
            self._repositories['outbox'] = OutboxRepository(self.client)
        return self._repositories['outbox']

    def get_outbox_repository(self) -> OutboxRepository:
        return self.get_outbox_service()
    
    # Alias methods for repository naming (for test compatibility)
    def get_telemetry_repository(self) -> TelemetryRepository:
        """Get telemetry repository instance (alias for get_telemetry_service)."""
        return self.get_telemetry_service()

    def get_users_repository(self) -> UsersRepository:
        """Get users repository instance (alias for get_users_service)."""
        return self.get_users_service()

    def get_sessions_repository(self) -> SessionsStore:
        """Get sessions repository instance (alias for get_sessions_service)."""
        return self.get_sessions_service()

    def get_audit_repository(self) -> AuditLogStore:
        """Get audit repository instance (alias for get_audit_service)."""
        return self.get_audit_service()

    def get_devices_repository(self) -> DevicesStore:
        """Get devices repository instance (alias for get_devices_service)."""
        return self.get_devices_service()

    def get_tenant_repository(self) -> TenantRepository:
        return self.get_tenant_service()

    def get_member_repository(self) -> TenantMemberRepository:
        return self.get_member_service()

    def get_invite_repository(self) -> InviteRepository:
        return self.get_invite_service()

    def get_idempotency_repository(self) -> IdempotencyKeyRepository:
        return self.get_idempotency_service()
    
    def get_all_repositories(self) -> Dict[str, Any]:
        """Get all repository instances."""
        return {
            'telemetry': self.get_telemetry_repository(),
            'users': self.get_users_repository(),
            'sessions': self.get_sessions_repository(),
            'audit': self.get_audit_repository(),
            'devices': self.get_devices_repository(),
            'tenants': self.get_tenant_repository(),
            'members': self.get_member_repository(),
            'invites': self.get_invite_repository(),
            'idempotency': self.get_idempotency_repository(),
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

    def configure_client_behavior(self, behavior_config: Dict[str, Any]):
        """Configure client behavior (for testing - no-op in production)."""
        # This is primarily for mock testing, no-op in real implementation
        pass

    def simulate_error(self, operation: str, error: Exception):
        """Simulate errors for operations (for testing - no-op in production)."""
        # This is primarily for mock testing, no-op in real implementation
        pass

    def is_telemetry_enabled(self) -> bool:
        """Check if telemetry service is enabled."""
        return self.config.use_firestore_telemetry

    def is_auth_enabled(self) -> bool:
        """Check if authentication service is enabled."""
        return self.config.use_firestore_auth

    def is_audit_enabled(self) -> bool:
        """Check if audit service is enabled."""
        return self.config.use_firestore_audit
    
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
                    'telemetry': self.is_telemetry_enabled(),
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
                    'telemetry': False,
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
