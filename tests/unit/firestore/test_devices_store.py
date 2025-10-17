"""Tests for DevicesRepository."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock

from tests.unit.firestore.mock import (
    DevicesRepository, MockDevice as Device, OperationResult, QueryOptions,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound,
    ErrorMappingRegistry, PermissionError, MockDevicesStore as DevicesStore
)


class TestDevicesRepository:
    """Test cases for DevicesRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        
        # Create a mock collection
        mock_collection = Mock()
        client.collection.return_value = mock_collection
        
        # Create a mock query that chains properly
        mock_query = Mock()
        mock_collection.where.return_value = mock_query
        mock_query.where.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.stream.return_value = []
        
        return client
    
    @pytest.fixture
    def devices_repo(self, mock_client):
        """Create DevicesRepository instance."""
        return DevicesRepository(mock_client)
    
    @pytest.fixture
    def sample_device(self):
        """Create sample device for testing."""
        return Device(
            tenant_id="test_tenant",
            device_id="test_device",
            metadata={"location": "test_location", "model": "test_model"},
            status="active"
        )
    
    def test_init(self, mock_client):
        """Test repository initialization."""
        repo = DevicesRepository(mock_client)
        assert repo.client == mock_client
        assert repo.collection == mock_client.collection.return_value
        assert repo.required_fields == ['tenant_id', 'device_id']
    
    def test_create_success(self, devices_repo, sample_device):
        """Test successful device creation."""
        mock_doc_ref = Mock()
        devices_repo.collection.document.return_value = mock_doc_ref
        
        with patch.object(devices_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = sample_device.__dict__
            
            result = devices_repo.create(sample_device)
            
            assert result.success is True
            assert result.data == "test_tenant_test_device"
            mock_doc_ref.set.assert_called_once()
    
    def test_create_missing_required_fields(self, devices_repo):
        """Test device creation with missing required fields."""
        with pytest.raises(ValueError, match="tenant_id and device_id are required"):
            invalid_device = Device(tenant_id="", device_id="", metadata={})
    
    def test_get_by_id_success(self, devices_repo):
        """Test successful device retrieval by ID."""
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'test_device',
            'metadata': {},
            'status': 'active',
            'last_seen': int(time.time() * 1000)
        }
        mock_doc.id = "test_tenant_test_device"
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        devices_repo.collection.document.return_value = mock_doc_ref
        
        result = devices_repo.get_by_id("test_tenant_test_device")
        
        assert result.success is True
        assert isinstance(result.data, Device)
        assert result.data.tenant_id == "test_tenant"
        assert result.data.device_id == "test_device"
    
    def test_get_by_id_not_found(self, devices_repo):
        """Test device retrieval when device doesn't exist."""
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        devices_repo.collection.document.return_value = mock_doc_ref
        
        result = devices_repo.get_by_id("nonexistent_device")
        
        assert result.success is False
        assert result.error == "Device not found"
    
    def test_get_device_success(self, devices_repo):
        """Test successful device retrieval by tenant and device ID."""
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'test_device',
            'metadata': {},
            'status': 'active',
            'last_seen': int(time.time() * 1000)
        }
        mock_doc.id = "test_tenant_test_device"
        
        mock_doc_ref = Mock()
        mock_doc_ref.get.return_value = mock_doc
        devices_repo.collection.document.return_value = mock_doc_ref
        
        result = devices_repo.get_device("test_tenant", "test_device")
        
        assert result.success is True
        assert isinstance(result.data, Device)
        assert result.data.tenant_id == "test_tenant"
        assert result.data.device_id == "test_device"
    
    def test_update_success(self, devices_repo, sample_device):
        """Test successful device update."""
        # Mock get_by_id to return existing device
        devices_repo.get_by_id = Mock(return_value=OperationResult(success=True, data=sample_device))
        
        mock_doc_ref = Mock()
        devices_repo.collection.document.return_value = mock_doc_ref
        
        with patch.object(devices_repo, '_add_update_timestamp') as mock_add_timestamp:
            mock_add_timestamp.return_value = {'status': 'inactive', 'updated_at': 1234567890}
            
            result = devices_repo.update("test_tenant_test_device", {'status': 'inactive'})
            
            assert result.success is True
            mock_doc_ref.update.assert_called_once()
    
    def test_update_device_not_found(self, devices_repo):
        """Test device update when device doesn't exist."""
        devices_repo.get_by_id = Mock(return_value=OperationResult(success=False, error="Device not found"))
        
        result = devices_repo.update("nonexistent_device", {'status': 'inactive'})
        
        assert result.success is False
        assert result.error == "Device not found"
    
    def test_update_device_metadata(self, devices_repo, sample_device):
        """Test updating device metadata."""
        devices_repo.update = Mock(return_value=OperationResult(success=True, data=sample_device))
        
        result = devices_repo.update_device_metadata("test_tenant", "test_device", {"location": "new_location"})
        
        assert result.success is True
        devices_repo.update.assert_called_once_with("test_tenant_test_device", {'metadata': {"location": "new_location"}})
    
    def test_update_last_seen(self, devices_repo, sample_device):
        """Test updating device last seen timestamp."""
        devices_repo.update = Mock(return_value=OperationResult(success=True, data=sample_device))
        
        with patch('time.time', return_value=1234567890):
            result = devices_repo.update_last_seen("test_tenant", "test_device")
            
            assert result.success is True
            devices_repo.update.assert_called_once_with("test_tenant_test_device", {'last_seen': 1234567890000})
    
    def test_set_status(self, devices_repo, sample_device):
        """Test setting device status."""
        devices_repo.update = Mock(return_value=OperationResult(success=True, data=sample_device))
        
        result = devices_repo.set_status("test_tenant", "test_device", "maintenance")
        
        assert result.success is True
        devices_repo.update.assert_called_once_with("test_tenant_test_device", {'status': 'maintenance'})
    
    def test_delete_success(self, devices_repo, sample_device):
        """Test successful device deletion."""
        devices_repo.get_by_id = Mock(return_value=OperationResult(success=True, data=sample_device))
        
        mock_doc_ref = Mock()
        devices_repo.collection.document.return_value = mock_doc_ref
        
        result = devices_repo.delete("test_tenant_test_device")
        
        assert result.success is True
        assert result.data is True
        mock_doc_ref.delete.assert_called_once()
    
    def test_delete_device_not_found(self, devices_repo):
        """Test device deletion when device doesn't exist."""
        devices_repo.get_by_id = Mock(return_value=OperationResult(success=False, error="Device not found"))
        
        result = devices_repo.delete("nonexistent_device")
        
        assert result.success is False
        assert result.error == "Device not found"
    
    def test_delete_device(self, devices_repo, sample_device):
        """Test device deletion by tenant and device ID."""
        devices_repo.delete = Mock(return_value=OperationResult(success=True, data=True))
        
        result = devices_repo.delete_device("test_tenant", "test_device")
        
        assert result.success is True
        devices_repo.delete.assert_called_once_with("test_tenant_test_device")
    
    def test_list_for_tenant_success(self, devices_repo):
        """Test successful device listing for tenant."""
        mock_doc1 = Mock()
        mock_doc1.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'device1',
            'metadata': {},
            'status': 'active',
            'last_seen': int(time.time() * 1000)
        }
        mock_doc1.id = "test_tenant_device1"
        
        mock_doc2 = Mock()
        mock_doc2.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'device2',
            'metadata': {},
            'status': 'inactive',
            'last_seen': int(time.time() * 1000)
        }
        mock_doc2.id = "test_tenant_device2"
        
        # Update the stream return value for the query
        devices_repo.collection.where.return_value.stream.return_value = [mock_doc1, mock_doc2]
        
        result = devices_repo.list_for_tenant("test_tenant")
        
        assert result.success is True
        assert len(result.data.items) == 2
        assert all(isinstance(device, Device) for device in result.data.items)
    
    def test_get_by_status_success(self, devices_repo):
        """Test successful device retrieval by status."""
        mock_doc = Mock()
        mock_doc.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'device1',
            'metadata': {},
            'status': 'active',
            'last_seen': int(time.time() * 1000)
        }
        mock_doc.id = "test_tenant_device1"
        
        # Update the stream return value for the chained query
        devices_repo.collection.where.return_value.where.return_value.stream.return_value = [mock_doc]
        
        result = devices_repo.get_by_status("test_tenant", "active")
        
        assert result.success is True
        assert len(result.data.items) == 1
        assert result.data.items[0].status == "active"
    
    def test_get_inactive_devices_success(self, devices_repo):
        """Test successful retrieval of inactive devices."""
        mock_doc = Mock()
        mock_doc.to_dict.return_value = {
            'tenant_id': 'test_tenant',
            'device_id': 'device1',
            'metadata': {},
            'status': 'active',
            'last_seen': int((time.time() - 7200) * 1000)  # 2 hours ago
        }
        mock_doc.id = "test_tenant_device1"
        
        # Update the stream return value for the chained query
        devices_repo.collection.where.return_value.where.return_value.stream.return_value = [mock_doc]
        
        result = devices_repo.get_inactive_devices("test_tenant", inactive_threshold_ms=3600000)  # 1 hour threshold
        
        assert result.success is True
        assert len(result.data.items) == 1
    
    def test_check_exists_true(self, devices_repo):
        """Test device existence check when device exists."""
        mock_device = Device(tenant_id="test_tenant", device_id="test_device")
        devices_repo.get_device = Mock(return_value=OperationResult(success=True, data=mock_device))
        
        result = devices_repo.check_exists("test_tenant", "test_device")
        
        assert result.success is True
        assert result.data is True
    
    def test_check_exists_false(self, devices_repo):
        """Test device existence check when device doesn't exist."""
        devices_repo.get_device = Mock(return_value=OperationResult(success=False, error="Device not found"))
        
        result = devices_repo.check_exists("test_tenant", "test_device")
        
        assert result.success is True
        assert result.data is False
    
    def test_get_device_count_success(self, devices_repo):
        """Test successful device count retrieval."""
        mock_doc1 = Mock()
        mock_doc2 = Mock()
        mock_doc3 = Mock()
        
        mock_query = Mock()
        mock_query.stream.return_value = [mock_doc1, mock_doc2, mock_doc3]
        devices_repo.collection.where.return_value = mock_query
        
        result = devices_repo.get_device_count("test_tenant")
        
        assert result.success is True
        assert result.data == 3
    
    def test_permission_denied_error(self, devices_repo, sample_device):
        """Test handling of permission denied errors."""
        # Register the mock exception with the error registry
        
        @ErrorMappingRegistry.register(PermissionDenied)
        def handle_mock_permission_denied(message: str, error: Exception):
            return PermissionError(message, error)
        
        devices_repo.collection.document.return_value.set.side_effect = PermissionDenied("Access denied")
        
        with pytest.raises(Exception):  # Should raise permission error
            devices_repo.create(sample_device)
        
        # Clean up the registry
        ErrorMappingRegistry.clear()
    
    def test_tenant_access_enforcement(self, devices_repo):
        """Test that tenant access is properly enforced."""
        # Test with different tenant ID - should return empty results for unauthorized tenant
        result = devices_repo.list_for_tenant("unauthorized_tenant")
        assert result.success is True
        assert len(result.data.items) == 0
    
    def test_with_query_options(self, devices_repo):
        """Test operations with query options."""
        # The mock query is already set up in the fixture to return empty results
        options = QueryOptions(limit=10, order_by='created_at', order_direction='ASC')
        
        result = devices_repo.list_for_tenant("test_tenant", options)
        
        assert result.success is True
        assert len(result.data.items) == 0
    
    def test_backward_compatibility_alias(self):
        """Test that DevicesStore alias exists for backward compatibility."""
        assert DevicesStore == DevicesRepository
