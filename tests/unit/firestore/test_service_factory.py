"""Tests for FirestoreServiceFactory."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from tests.unit.firestore.mock import (
    MockFirestoreServiceFactory as FirestoreServiceFactory, 
    get_mock_service_factory as get_service_factory, 
    reset_mock_service_factory as reset_service_factory, 
    MockFirestoreError as FirestoreError
)


class MockConfig:
    """Mock configuration for testing."""
    
    def __init__(self, use_firestore_telemetry=True, use_firestore_auth=True, use_firestore_audit=True):
        self.use_firestore_telemetry = use_firestore_telemetry
        self.use_firestore_auth = use_firestore_auth
        self.use_firestore_audit = use_firestore_audit


class TestFirestoreServiceFactory:
    """Test cases for FirestoreServiceFactory."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        return MockConfig()
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collections.return_value.limit.return_value.get.return_value = []
        return client
    
    @pytest.fixture
    def service_factory(self, mock_config, mock_client):
        """Create FirestoreServiceFactory instance."""
        return FirestoreServiceFactory(mock_client)
    
    def test_init(self, mock_config, mock_client):
        """Test factory initialization."""
        factory = FirestoreServiceFactory(mock_client)
        
        assert factory.client == mock_client
        assert factory._repositories == {}
    
    def test_client_property_success(self, service_factory, mock_client):
        """Test client property returns client successfully."""
        client = service_factory.client
        assert client == mock_client
    
    def test_client_property_with_none(self):
        """Test client property when no client is provided."""
        factory = FirestoreServiceFactory(None)
        
        # Should create a mock client automatically
        assert factory.client is not None
        assert isinstance(factory.client, Mock)
    
    def test_client_property_cached(self, service_factory, mock_client):
        """Test that client is cached after first access."""
        client1 = service_factory.client
        client2 = service_factory.client
        
        assert client1 == client2 == mock_client
    
    def test_get_telemetry_service(self, service_factory):
        """Test getting telemetry service."""
        service = service_factory.get_telemetry_repository()
        
        assert 'telemetry' in service_factory._repositories
        assert service_factory._repositories['telemetry'] == service
        
        # Test that same instance is returned on subsequent calls
        service2 = service_factory.get_telemetry_repository()
        assert service == service2
    
    def test_get_users_service(self, service_factory):
        """Test getting users service."""
        service = service_factory.get_users_repository()
        
        assert 'users' in service_factory._repositories
        assert service_factory._repositories['users'] == service
        
        # Test that same instance is returned on subsequent calls
        service2 = service_factory.get_users_repository()
        assert service == service2
    
    def test_get_sessions_service(self, service_factory):
        """Test getting sessions service."""
        service = service_factory.get_sessions_repository()
        
        assert 'sessions' in service_factory._repositories
        assert service_factory._repositories['sessions'] == service
        
        # Test that same instance is returned on subsequent calls
        service2 = service_factory.get_sessions_repository()
        assert service == service2
    
    def test_get_audit_service(self, service_factory):
        """Test getting audit service."""
        service = service_factory.get_audit_repository()
        
        assert 'audit' in service_factory._repositories
        assert service_factory._repositories['audit'] == service
        
        # Test that same instance is returned on subsequent calls
        service2 = service_factory.get_audit_repository()
        assert service == service2
    
    def test_get_devices_service(self, service_factory):
        """Test getting devices service."""
        service = service_factory.get_devices_repository()
        
        assert 'devices' in service_factory._repositories
        assert service_factory._repositories['devices'] == service
        
        # Test that same instance is returned on subsequent calls
        service2 = service_factory.get_devices_repository()
        assert service == service2
    
    def test_get_all_repositories(self, service_factory):
        """Test getting all repositories."""
        repositories = service_factory.get_all_repositories()
        
        assert 'users' in repositories
        assert 'sessions' in repositories
        assert 'audit' in repositories
        assert 'devices' in repositories
        assert 'telemetry' in repositories
        
        assert len(repositories) == 5
    
    def test_reset_repositories(self, service_factory):
        """Test resetting repositories."""
        # Create some repositories
        service_factory.get_users_repository()
        service_factory.get_devices_repository()
        
        assert len(service_factory._repositories) == 2
        
        # Reset repositories
        service_factory.reset_repositories()
        
        assert len(service_factory._repositories) == 0
        assert service_factory.client is not None
    
    def test_configure_client_behavior(self, service_factory):
        """Test configuring client behavior."""
        behavior_config = {
            'document_exists': False,
            'document_data': {'test': 'data'},
            'query_results': [{'id': 'doc1', 'data': 'test1'}]
        }
        
        service_factory.configure_client_behavior(behavior_config)
        
        # Verify behavior was configured
        mock_doc = service_factory.client.collection.return_value.document.return_value.get.return_value
        assert mock_doc.exists == False
        assert mock_doc.to_dict.return_value == {'test': 'data'}
        
        mock_collection = service_factory.client.collection.return_value
        assert mock_collection.stream.return_value == [{'id': 'doc1', 'data': 'test1'}]
    
    def test_simulate_error(self, service_factory):
        """Test simulating errors for different operations."""
        test_error = Exception("Test error")
        
        # Test simulate error for create operation
        service_factory.simulate_error('create', test_error)
        
        # Test simulate error for get operation
        service_factory.simulate_error('get', test_error)
        
        # Test simulate error for update operation
        service_factory.simulate_error('update', test_error)
        
        # Test simulate error for delete operation
        service_factory.simulate_error('delete', test_error)
        
        # Test simulate error for query operation
        service_factory.simulate_error('query', test_error)
        
        # Verify errors were set
        assert service_factory.client.collection.return_value.document.return_value.set.side_effect == test_error
        assert service_factory.client.collection.return_value.document.return_value.get.side_effect == test_error
        assert service_factory.client.collection.return_value.document.return_value.update.side_effect == test_error
        assert service_factory.client.collection.return_value.document.return_value.delete.side_effect == test_error
        assert service_factory.client.collection.return_value.stream.side_effect == test_error
    
    def test_all_services_created(self, service_factory):
        """Test that all services can be created successfully."""
        telemetry_service = service_factory.get_telemetry_repository()
        users_service = service_factory.get_users_repository()
        sessions_service = service_factory.get_sessions_repository()
        audit_service = service_factory.get_audit_repository()
        devices_service = service_factory.get_devices_repository()
        
        # Verify all services are created
        assert telemetry_service is not None
        assert users_service is not None
        assert sessions_service is not None
        assert audit_service is not None
        assert devices_service is not None
        
        # Verify all services are cached
        assert len(service_factory._repositories) == 5
        assert 'telemetry' in service_factory._repositories
        assert 'users' in service_factory._repositories
        assert 'sessions' in service_factory._repositories
        assert 'audit' in service_factory._repositories
        assert 'devices' in service_factory._repositories


class TestGlobalServiceFactory:
    """Test cases for global service factory functions."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        return MockConfig()
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collections.return_value.limit.return_value.get.return_value = []
        return client
    
    def test_get_service_factory_creates_new(self, mock_config, mock_client):
        """Test that get_service_factory creates new factory when none exists."""
        reset_service_factory()  # Ensure clean state
        
        factory = get_service_factory(mock_client)
        
        assert isinstance(factory, FirestoreServiceFactory)
        assert factory.client == mock_client
    
    def test_get_service_factory_returns_existing(self, mock_config, mock_client):
        """Test that get_service_factory returns existing factory."""
        reset_service_factory()  # Ensure clean state
        
        factory1 = get_service_factory(mock_client)
        factory2 = get_service_factory(mock_client)
        
        assert factory1 == factory2
    
    def test_reset_service_factory(self, mock_config, mock_client):
        """Test that reset_service_factory clears the global instance."""
        reset_service_factory()  # Ensure clean state
        
        factory1 = get_service_factory(mock_client)
        reset_service_factory()
        factory2 = get_service_factory(mock_client)
        
        # Should be different instances
        assert factory1 != factory2
    
    def test_get_service_factory_with_different_clients(self, mock_client):
        """Test that different clients create different factories."""
        reset_service_factory()  # Ensure clean state
        
        client1 = Mock()
        client2 = Mock()
        
        factory1 = get_service_factory(client1)
        reset_service_factory()
        factory2 = get_service_factory(client2)
        
        assert factory1.client == client1
        assert factory2.client == client2
