"""Mock service factory for creating mock Firestore repositories."""

import logging
from typing import Dict, Any, Optional
from unittest.mock import Mock

from .mock_users_store import MockUsersRepository
from .mock_sessions_store import MockSessionsRepository
from .mock_audit_store import MockAuditRepository
from .mock_devices_store import MockDevicesRepository
from .mock_telemetry_store import MockTelemetryRepository

logger = logging.getLogger(__name__)


class MockFirestoreServiceFactory:
    """Factory for creating mock Firestore service instances."""
    
    def __init__(self, client: Optional[Mock] = None):
        """Initialize with optional mock Firestore client."""
        self.client = client or self._create_mock_client()
        self._repositories: Dict[str, Any] = {}
    
    def _create_mock_client(self) -> Mock:
        """Create a mock Firestore client."""
        mock_client = Mock()
        
        # Mock collection method
        mock_collection = Mock()
        mock_client.collection.return_value = mock_collection
        
        # Mock document method on collection
        mock_doc_ref = Mock()
        mock_collection.document.return_value = mock_doc_ref
        
        # Mock document operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {}
        mock_doc.id = "mock_doc_id"
        mock_doc_ref.get.return_value = mock_doc
        
        # Mock collection operations
        mock_collection.add.return_value = (None, mock_doc_ref)
        mock_collection.where.return_value = mock_collection
        mock_collection.stream.return_value = []
        mock_collection.order_by.return_value = mock_collection
        mock_collection.limit.return_value = mock_collection
        mock_collection.start_after.return_value = mock_collection
        
        return mock_client
    
    def get_users_repository(self) -> MockUsersRepository:
        """Get or create users repository."""
        if 'users' not in self._repositories:
            self._repositories['users'] = MockUsersRepository(self.client)
        return self._repositories['users']
    
    def get_sessions_repository(self) -> MockSessionsRepository:
        """Get or create sessions repository."""
        if 'sessions' not in self._repositories:
            self._repositories['sessions'] = MockSessionsRepository(self.client)
        return self._repositories['sessions']
    
    def get_audit_repository(self) -> MockAuditRepository:
        """Get or create audit repository."""
        if 'audit' not in self._repositories:
            self._repositories['audit'] = MockAuditRepository(self.client)
        return self._repositories['audit']
    
    def get_devices_repository(self) -> MockDevicesRepository:
        """Get or create devices repository."""
        if 'devices' not in self._repositories:
            self._repositories['devices'] = MockDevicesRepository(self.client)
        return self._repositories['devices']
    
    def get_telemetry_repository(self) -> MockTelemetryRepository:
        """Get or create telemetry repository."""
        if 'telemetry' not in self._repositories:
            self._repositories['telemetry'] = MockTelemetryRepository(self.client)
        return self._repositories['telemetry']
    
    def get_all_repositories(self) -> Dict[str, Any]:
        """Get all repositories."""
        return {
            'users': self.get_users_repository(),
            'sessions': self.get_sessions_repository(),
            'audit': self.get_audit_repository(),
            'devices': self.get_devices_repository(),
            'telemetry': self.get_telemetry_repository()
        }
    
    def reset_repositories(self) -> None:
        """Reset all repositories (useful for test cleanup)."""
        self._repositories.clear()
        self.client = self._create_mock_client()
    
    def configure_client_behavior(self, behavior_config: Dict[str, Any]) -> None:
        """Configure mock client behavior for testing."""
        # Example: Configure specific responses for testing
        if 'document_exists' in behavior_config:
            mock_doc = self.client.collection.return_value.document.return_value.get.return_value
            mock_doc.exists = behavior_config['document_exists']
        
        if 'document_data' in behavior_config:
            mock_doc = self.client.collection.return_value.document.return_value.get.return_value
            mock_doc.to_dict.return_value = behavior_config['document_data']
        
        if 'query_results' in behavior_config:
            mock_collection = self.client.collection.return_value
            mock_collection.stream.return_value = behavior_config['query_results']
    
    def simulate_error(self, operation: str, error: Exception) -> None:
        """Simulate an error for a specific operation."""
        if operation == 'create':
            self.client.collection.return_value.document.return_value.set.side_effect = error
        elif operation == 'get':
            self.client.collection.return_value.document.return_value.get.side_effect = error
        elif operation == 'update':
            self.client.collection.return_value.document.return_value.update.side_effect = error
        elif operation == 'delete':
            self.client.collection.return_value.document.return_value.delete.side_effect = error
        elif operation == 'query':
            self.client.collection.return_value.stream.side_effect = error


# Global factory instance for easy access
_mock_factory: Optional[MockFirestoreServiceFactory] = None


def get_mock_service_factory(client: Optional[Mock] = None) -> MockFirestoreServiceFactory:
    """Get or create global mock service factory."""
    global _mock_factory
    if _mock_factory is None:
        _mock_factory = MockFirestoreServiceFactory(client)
    return _mock_factory


def reset_mock_service_factory() -> None:
    """Reset global mock service factory."""
    global _mock_factory
    _mock_factory = None


# Convenience functions for getting individual repositories
def get_mock_users_repository() -> MockUsersRepository:
    """Get mock users repository."""
    return get_mock_service_factory().get_users_repository()


def get_mock_sessions_repository() -> MockSessionsRepository:
    """Get mock sessions repository."""
    return get_mock_service_factory().get_sessions_repository()


def get_mock_audit_repository() -> MockAuditRepository:
    """Get mock audit repository."""
    return get_mock_service_factory().get_audit_repository()


def get_mock_devices_repository() -> MockDevicesRepository:
    """Get mock devices repository."""
    return get_mock_service_factory().get_devices_repository()


def get_mock_telemetry_repository() -> MockTelemetryRepository:
    """Get mock telemetry repository."""
    return get_mock_service_factory().get_telemetry_repository()


# Backward compatibility aliases
FirestoreServiceFactory = MockFirestoreServiceFactory
UsersRepository = MockUsersRepository
SessionsRepository = MockSessionsRepository
AuditRepository = MockAuditRepository
DevicesRepository = MockDevicesRepository
TelemetryRepository = MockTelemetryRepository
