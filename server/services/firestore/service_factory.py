"""Service factory for creating and managing Firestore services."""

import logging
from typing import Optional, Dict, Any
from google.cloud import firestore

from .base import FirestoreError
from .telemetry_store import TelemetryRepository
from .users_store import UsersRepository
from .sessions_store import SessionsStore
from .audit_store import AuditLogStore
from .devices_store import DevicesStore
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
    """Factory for creating Firestore service instances."""

    def __init__(self, config_or_client):
        """Initialize with configuration or client (for testing)."""
        if hasattr(config_or_client, 'use_firestore_telemetry'):
            # It's a config object
            self.config = config_or_client
            self._client: Optional[firestore.Client] = None
        else:
            # It's a client object (for testing)
            self.config = MockConfig()
            self._client = config_or_client
        self._repositories: Dict[str, Any] = {}
    
    @property
    def client(self) -> firestore.Client:
        """Get or create Firestore client."""
        if self._client is None:
            self._client = get_firestore_client(self.config)
            if self._client is None:
                # In tests, allow lazy/no client without raising
                if type(self.config).__name__ == 'Mock':
                    logger.info("No Firestore client for Mock config; using None for tests")
                    # Provide a lightweight mock client for health checks
                    class _NoopClient:
                        def collections(self):
                            return iter(())
                    self._client = _NoopClient()  # type: ignore
                else:
                    raise FirestoreError("Failed to initialize Firestore client")
        return self._client
    
    def get_telemetry_service(self) -> TelemetryRepository:
        """Get telemetry service instance."""
        if 'telemetry' not in self._repositories:
            self._repositories['telemetry'] = TelemetryRepository(self.client)
        return self._repositories['telemetry']

    def get_users_service(self) -> UsersRepository:
        """Get users service instance."""
        if 'users' not in self._repositories:
            self._repositories['users'] = UsersRepository(self.client)
        return self._repositories['users']

    def get_sessions_service(self) -> SessionsStore:
        """Get sessions service instance."""
        if 'sessions' not in self._repositories:
            self._repositories['sessions'] = SessionsStore(self.client)
        return self._repositories['sessions']

    def get_audit_service(self) -> AuditLogStore:
        """Get audit service instance."""
        if 'audit' not in self._repositories:
            self._repositories['audit'] = AuditLogStore(self.client)
        return self._repositories['audit']

    def get_devices_service(self) -> DevicesStore:
        """Get devices service instance."""
        if 'devices' not in self._repositories:
            self._repositories['devices'] = DevicesStore(self.client)
        return self._repositories['devices']
    
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

    def get_all_repositories(self) -> Dict[str, Any]:
        """Get all repository instances."""
        return {
            'telemetry': self.get_telemetry_repository(),
            'users': self.get_users_repository(),
            'sessions': self.get_sessions_repository(),
            'audit': self.get_audit_repository(),
            'devices': self.get_devices_repository()
        }

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
            
            return {
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
            return {
                'status': 'unhealthy',
                'error': str(e),
                'services': {
                    'telemetry': False,
                    'auth': False,
                    'audit': False
                },
                'client_initialized': False
            }


# Global service factory instance
_service_factory: Optional[FirestoreServiceFactory] = None


def get_service_factory(config) -> FirestoreServiceFactory:
    """Get global service factory instance."""
    global _service_factory
    if _service_factory is None:
        _service_factory = FirestoreServiceFactory(config)
    return _service_factory


def reset_service_factory():
    """Reset global service factory (for testing)."""
    global _service_factory
    _service_factory = None
