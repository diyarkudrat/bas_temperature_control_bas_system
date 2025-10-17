"""Service factory for creating and managing Firestore services."""

import logging
from typing import Optional, Dict, Any
from google.cloud import firestore

from .base import FirestoreError
from .telemetry_store import TelemetryRepository
from .users_store import UsersRepository
from .sessions_store import SessionsRepository
from .audit_store import AuditLogRepository
from .devices_store import DevicesRepository
from ..firestore_client import get_firestore_client

logger = logging.getLogger(__name__)


class FirestoreServiceFactory:
    """Factory for creating Firestore service instances."""
    
    def __init__(self, config):
        """Initialize with configuration."""
        self.config = config
        self._client: Optional[firestore.Client] = None
        self._services: Dict[str, Any] = {}
    
    @property
    def client(self) -> firestore.Client:
        """Get or create Firestore client."""
        if self._client is None:
            self._client = get_firestore_client(self.config)
            if self._client is None:
                raise FirestoreError("Failed to initialize Firestore client")
        return self._client
    
    def get_telemetry_service(self) -> TelemetryRepository:
        """Get telemetry service instance."""
        if 'telemetry' not in self._services:
            self._services['telemetry'] = TelemetryRepository(self.client)
        return self._services['telemetry']
    
    def get_users_service(self) -> UsersRepository:
        """Get users service instance."""
        if 'users' not in self._services:
            self._services['users'] = UsersRepository(self.client)
        return self._services['users']
    
    def get_sessions_service(self) -> SessionsRepository:
        """Get sessions service instance."""
        if 'sessions' not in self._services:
            self._services['sessions'] = SessionsRepository(self.client)
        return self._services['sessions']
    
    def get_audit_service(self) -> AuditLogRepository:
        """Get audit service instance."""
        if 'audit' not in self._services:
            self._services['audit'] = AuditLogRepository(self.client)
        return self._services['audit']
    
    def get_devices_service(self) -> DevicesRepository:
        """Get devices service instance."""
        if 'devices' not in self._services:
            self._services['devices'] = DevicesRepository(self.client)
        return self._services['devices']
    
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
            # Test basic connectivity
            self.client.collections().limit(1).get()
            
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
