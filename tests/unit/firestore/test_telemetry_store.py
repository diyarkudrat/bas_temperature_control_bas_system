"""Tests for TelemetryRepository."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    TelemetryRepository, MockTelemetryRecord as TelemetryRecord, create_mock_telemetry_record as create_telemetry_record,
    OperationResult, QueryOptions, PaginatedResult, FirestoreError, PermissionError, ValidationError,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestTelemetryRepository:
    """Test cases for TelemetryRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def telemetry_repo(self, mock_client):
        """Create TelemetryRepository instance."""
        return TelemetryRepository(mock_client)
    
    @pytest.fixture
    def sample_telemetry(self):
        """Create sample telemetry record for testing."""
        return TelemetryRecord(
            tenant_id="test_tenant",
            device_id="test_device",
            timestamp_ms=int(time.time() * 1000),
            utc_timestamp=datetime.utcnow().isoformat() + 'Z',
            temp_tenths=230,
            setpoint_tenths=240,
            deadband_tenths=10,
            cool_active=False,
            heat_active=True,
            state="HEATING",
            sensor_ok=True
        )
    
    def test_init(self, mock_client):
        """Test repository initialization."""
        repo = TelemetryRepository(mock_client)
        assert repo.client == mock_client
        assert repo.collection == mock_client.collection.return_value
        assert repo.required_fields == ['tenant_id', 'device_id', 'temp_tenths', 'sensor_ok']
    
    def test_create_success(self, telemetry_repo, sample_telemetry):
        """Test successful telemetry record creation."""
        mock_doc_ref = Mock()
        mock_doc_ref.id = "test_doc_id"
        telemetry_repo.collection.add.return_value = (Mock(), mock_doc_ref)
        
        with patch.object(telemetry_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = sample_telemetry.to_dict()
            
            result = telemetry_repo.create(sample_telemetry)
            
            assert_true(result.success, "Create should succeed")
            assert_equals(result.data, "test_doc_id", "Should return document ID")
            telemetry_repo.collection.add.assert_called_once()
    
    def test_create_validation_error(self, telemetry_repo):
        """Test create with validation error."""
        # Test with invalid data that should trigger validation error
        invalid_telemetry = TelemetryRecord(
            tenant_id="valid_tenant",  # Valid tenant_id to avoid model validation
            device_id="test_device",
            timestamp_ms=int(time.time() * 1000),
            utc_timestamp=datetime.utcnow().isoformat() + 'Z',
            temp_tenths=230,
            setpoint_tenths=240,
            deadband_tenths=10,
            cool_active=False,
            heat_active=True,
            state="HEATING",
            sensor_ok=True
        )
        
        # Mock the validation to fail
        with patch.object(telemetry_repo, '_validate_required_fields') as mock_validate:
            mock_validate.side_effect = ValidationError("Validation failed")
            
            with assert_raises(ValidationError):
                telemetry_repo.create(invalid_telemetry)
    
    def test_create_missing_required_fields(self, telemetry_repo, sample_telemetry):
        """Test create with missing required fields."""
        # Remove required field
        data = sample_telemetry.to_dict()
        del data['tenant_id']
        
        with patch.object(telemetry_repo, '_validate_required_fields') as mock_validate:
            mock_validate.side_effect = ValidationError("Missing required fields")
            
            with assert_raises(ValidationError):
                telemetry_repo.create(sample_telemetry)
    
    def test_create_permission_denied(self, telemetry_repo, sample_telemetry):
        """Test create with permission denied error."""
        telemetry_repo.collection.add.side_effect = PermissionDenied("Permission denied")
        
        with patch.object(telemetry_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = sample_telemetry.to_dict()
            
            with assert_raises(PermissionError):
                telemetry_repo.create(sample_telemetry)
    
    def test_get_by_id_success(self, telemetry_repo, sample_telemetry):
        """Test successful get by ID."""
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.id = "test_doc_id"
        mock_doc.to_dict.return_value = sample_telemetry.to_dict()
        
        telemetry_repo.collection.document.return_value.get.return_value = mock_doc
        
        with patch('tests.unit.firestore.mock.mock_models.create_mock_telemetry_record') as mock_create:
            mock_create.return_value = sample_telemetry
            
            result = telemetry_repo.get_by_id("test_doc_id")
            
            assert_true(result.success, "Get should succeed")
            assert_is_not_none(result.data, "Should return telemetry record")
            assert_equals(result.data.id, "test_doc_id", "Should set document ID")
    
    def test_get_by_id_not_found(self, telemetry_repo):
        """Test get by ID when document doesn't exist."""
        mock_doc = Mock()
        mock_doc.exists = False
        
        telemetry_repo.collection.document.return_value.get.return_value = mock_doc
        
        result = telemetry_repo.get_by_id("nonexistent_id")
        
        assert_false(result.success, "Get should fail")
        assert_equals(result.error, "Record not found", "Should return not found error")
        assert_equals(result.error_code, "NOT_FOUND", "Should return correct error code")
    
    def test_get_by_id_permission_denied(self, telemetry_repo):
        """Test get by ID with permission denied error."""
        telemetry_repo.collection.document.return_value.get.side_effect = PermissionDenied("Permission denied")
        
        with assert_raises(PermissionError):
            telemetry_repo.get_by_id("test_id")
    
    def test_update_success(self, telemetry_repo, sample_telemetry):
        """Test successful telemetry record update."""
        updates = {'temp_tenths': 250, 'state': 'COOLING'}
        
        with patch.object(telemetry_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = updates
        with patch.object(telemetry_repo, 'get_by_id') as mock_get_by_id:
            mock_get_by_id.return_value = OperationResult(success=True, data=sample_telemetry)
            
            result = telemetry_repo.update("test_doc_id", updates)
            
            assert_true(result.success, "Update should succeed")
            telemetry_repo.collection.document.return_value.update.assert_called_once()
    
    def test_update_permission_denied(self, telemetry_repo):
        """Test update with permission denied error."""
        updates = {'temp_tenths': 250}
        telemetry_repo.collection.document.return_value.update.side_effect = PermissionDenied("Permission denied")
        
        with patch.object(telemetry_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = updates
            
            with assert_raises(PermissionError):
                telemetry_repo.update("test_id", updates)
    
    def test_delete_success(self, telemetry_repo):
        """Test successful telemetry record deletion."""
        result = telemetry_repo.delete("test_doc_id")
        
        assert_true(result.success, "Delete should succeed")
        assert_true(result.data, "Should return True")
        telemetry_repo.collection.document.return_value.delete.assert_called_once()
    
    def test_delete_permission_denied(self, telemetry_repo):
        """Test delete with permission denied error."""
        telemetry_repo.collection.document.return_value.delete.side_effect = PermissionDenied("Permission denied")
        
        with assert_raises(PermissionError):
            telemetry_repo.delete("test_id")
    
    def test_query_recent_for_device_success(self, telemetry_repo, sample_telemetry):
        """Test successful recent telemetry query for device."""
        options = QueryOptions(limit=10)
        
        # Create mock result directly
        expected_result = PaginatedResult(
            items=[sample_telemetry, sample_telemetry],
            has_more=False,
            next_offset="doc2"
        )
        
        with patch.object(telemetry_repo, '_execute_query') as mock_execute_query:
            mock_execute_query.return_value = expected_result
            
            result = telemetry_repo.query_recent_for_device("test_tenant", "test_device", options)
            
            assert_is_instance(result, PaginatedResult, "Should return PaginatedResult")
            assert_equals(len(result.items), 2, "Should return 2 items")
            assert_equals(result.next_offset, "doc2", "Should set next_offset")
            assert_false(result.has_more, "Should not have more items")
    
    def test_query_recent_for_device_permission_denied(self, telemetry_repo):
        """Test recent query with permission denied error."""
        options = QueryOptions(limit=10)
        
        with patch.object(telemetry_repo, '_apply_query_options') as mock_apply_options:
            mock_apply_options.return_value.stream.side_effect = PermissionDenied("Permission denied")
            
            with assert_raises(PermissionError):
                telemetry_repo.query_recent_for_device("test_tenant", "test_device", options)
    
    def test_query_time_window_success(self, telemetry_repo, sample_telemetry):
        """Test successful time window query."""
        start_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        end_time = int(time.time() * 1000)
        options = QueryOptions(limit=100)
        
        # Create mock result directly
        expected_result = PaginatedResult(
            items=[sample_telemetry],
            has_more=False,
            next_offset=None
        )
        
        with patch.object(telemetry_repo, '_execute_query') as mock_execute_query:
            mock_execute_query.return_value = expected_result
            
            result = telemetry_repo.query_time_window("test_tenant", "test_device", start_time, end_time, options)
            
            assert_is_instance(result, PaginatedResult, "Should return PaginatedResult")
            assert_equals(len(result.items), 1, "Should return 1 item")
    
    def test_query_time_window_permission_denied(self, telemetry_repo):
        """Test time window query with permission denied error."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        options = QueryOptions(limit=100)
        
        with patch.object(telemetry_repo, '_apply_query_options') as mock_apply_options:
            mock_apply_options.return_value.stream.side_effect = PermissionDenied("Permission denied")
            
            with assert_raises(PermissionError):
                telemetry_repo.query_time_window("test_tenant", "test_device", start_time, end_time, options)
    
    def test_get_device_statistics_success(self, telemetry_repo, sample_telemetry):
        """Test successful device statistics generation."""
        # Create multiple telemetry records for statistics
        telemetry_records = [
            TelemetryRecord(
                tenant_id="test_tenant",
                device_id="test_device",
                timestamp_ms=int(time.time() * 1000),
                utc_timestamp=datetime.utcnow().isoformat() + 'Z',
                temp_tenths=220,
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=False,
                heat_active=True,
                state="HEATING",
                sensor_ok=True
            ),
            TelemetryRecord(
                tenant_id="test_tenant",
                device_id="test_device",
                timestamp_ms=int(time.time() * 1000),
                utc_timestamp=datetime.utcnow().isoformat() + 'Z',
                temp_tenths=240,
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=True,
                heat_active=False,
                state="COOLING",
                sensor_ok=True
            ),
            TelemetryRecord(
                tenant_id="test_tenant",
                device_id="test_device",
                timestamp_ms=int(time.time() * 1000),
                utc_timestamp=datetime.utcnow().isoformat() + 'Z',
                temp_tenths=0,  # Sensor failure
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=False,
                heat_active=False,
                state="ERROR",
                sensor_ok=False
            )
        ]
        
        # Mock the get_statistics_for_device method directly
        with patch.object(telemetry_repo, 'get_statistics_for_device') as mock_get_stats:
            mock_get_stats.return_value = OperationResult(success=True, data={
                'record_count': 3,
                'temp_min': 220,
                'temp_max': 240,
                'temp_avg': 230,
                'setpoint_min': 240,
                'setpoint_max': 240,
                'setpoint_avg': 240,
                'cool_active_count': 1,
                'heat_active_count': 1,
                'sensor_failures': 1
            })
            
            stats = telemetry_repo.get_device_statistics("test_tenant", "test_device", 24)
            
            assert_equals(stats['total_records'], 3, "Should count all records")
            assert_equals(stats['avg_temperature'], 230, "Should calculate average temperature")
            assert_equals(stats['min_temperature'], 220, "Should find minimum temperature")
            assert_equals(stats['max_temperature'], 240, "Should find maximum temperature")
            assert_equals(stats['sensor_failures'], 1, "Should count sensor failures")
            assert_equals(stats['uptime_percentage'], 66.67, "Should calculate uptime percentage")
    
    def test_get_device_statistics_no_data(self, telemetry_repo):
        """Test device statistics with no data."""
        with patch.object(telemetry_repo, 'query_time_window') as mock_query:
            mock_query.return_value = PaginatedResult(items=[], has_more=False)
            
            stats = telemetry_repo.get_device_statistics("test_tenant", "test_device", 24)
            
            assert_equals(stats['total_records'], 0, "Should return zero records")
            assert_equals(stats['avg_temperature'], 0, "Should return zero average")
            assert_equals(stats['uptime_percentage'], 0, "Should return zero uptime")
    
    def test_get_device_statistics_permission_denied(self, telemetry_repo):
        """Test device statistics with permission denied error."""
        with patch.object(telemetry_repo, 'get_statistics_for_device') as mock_get_stats:
            mock_get_stats.side_effect = PermissionError("Permission denied")
            
            # The method catches exceptions and returns default stats, so test that behavior
            stats = telemetry_repo.get_device_statistics("test_tenant", "test_device", 24)
            
            # Should return default stats when error occurs
            assert_equals(stats['total_records'], 0, "Should return zero records on error")
            assert_equals(stats['avg_temperature'], 0, "Should return zero average on error")
            assert_equals(stats['uptime_percentage'], 0, "Should return zero uptime on error")
    
    # Legacy compatibility methods tests
    def test_add_telemetry_legacy_success(self, telemetry_repo):
        """Test legacy add_telemetry method."""
        data = {
            'timestamp': time.time() * 1000,
            'temp_tenths': 230,
            'setpoint_tenths': 240,
            'deadband_tenths': 10,
            'cool_active': False,
            'heat_active': True,
            'state': 'HEATING',
            'sensor_ok': True
        }
        
        with patch.object(telemetry_repo, 'create') as mock_create:
            mock_create.return_value = OperationResult(success=True, data="test_doc_id")
            
            result = telemetry_repo.add_telemetry("test_tenant", "test_device", data)
            
            assert_true(result, "Legacy add_telemetry should succeed")
            mock_create.assert_called_once()
    
    def test_add_telemetry_legacy_failure(self, telemetry_repo):
        """Test legacy add_telemetry method with failure."""
        data = {'temp_tenths': 230}
        
        with patch.object(telemetry_repo, 'create') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = telemetry_repo.add_telemetry("test_tenant", "test_device", data)
            
            assert_false(result, "Legacy add_telemetry should fail")
    
    def test_query_recent_legacy_success(self, telemetry_repo, sample_telemetry):
        """Test legacy query_recent method."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.return_value = PaginatedResult(items=[sample_telemetry], has_more=False)
            
            result = telemetry_repo.query_recent("test_tenant", "test_device", 100)
            
            assert_equals(len(result), 1, "Should return 1 item")
            assert_is_instance(result[0], dict, "Should return dict format")
    
    def test_query_recent_legacy_failure(self, telemetry_repo):
        """Test legacy query_recent method with failure."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.side_effect = Exception("Test error")
            
            result = telemetry_repo.query_recent("test_tenant", "test_device", 100)
            
            assert_equals(result, [], "Should return empty list on failure")
    
    def test_query_window_legacy_success(self, telemetry_repo, sample_telemetry):
        """Test legacy query_window method."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        
        with patch.object(telemetry_repo, 'query_by_timestamp_range') as mock_query:
            mock_query.return_value = PaginatedResult(items=[sample_telemetry], has_more=False)
            
            result = telemetry_repo.query_window("test_tenant", "test_device", start_time, end_time, 1000)
            
            assert_equals(len(result), 1, "Should return 1 item")
            assert_is_instance(result[0], dict, "Should return dict format")
    
    def test_query_recent_paginated_legacy_success(self, telemetry_repo, sample_telemetry):
        """Test legacy query_recent_paginated method."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.return_value = PaginatedResult(
                items=[sample_telemetry], 
                has_more=True, 
                next_offset="next_doc_id"
            )
            
            result = telemetry_repo.query_recent_paginated("test_tenant", "test_device", 100)
            
            assert_equals(len(result['data']), 1, "Should return 1 item in data")
            assert_equals(result['last_doc_id'], "next_doc_id", "Should return next doc ID")
            assert_true(result['has_more'], "Should indicate more data available")
    
    def test_query_recent_paginated_legacy_failure(self, telemetry_repo):
        """Test legacy query_recent_paginated method with failure."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.side_effect = Exception("Test error")
            
            result = telemetry_repo.query_recent_paginated("test_tenant", "test_device", 100)
            
            assert_equals(result['data'], [], "Should return empty data on failure")
            assert_false(result['has_more'], "Should indicate no more data")
    
    def test_get_device_count_success(self, telemetry_repo):
        """Test successful device count retrieval."""
        # Mock the _apply_query_options method to return a mock that yields documents
        mock_doc1 = Mock()
        mock_doc1.to_dict.return_value = {'device_id': 'device1'}
        
        mock_doc2 = Mock()
        mock_doc2.to_dict.return_value = {'device_id': 'device2'}
        
        mock_doc3 = Mock()
        mock_doc3.to_dict.return_value = {'device_id': 'device1'}  # Duplicate
        
        mock_stream = [mock_doc1, mock_doc2, mock_doc3]
        
        with patch.object(telemetry_repo, '_apply_query_options') as mock_apply_options:
            mock_query = Mock()
            mock_query.stream.return_value = mock_stream
            mock_apply_options.return_value = mock_query
            
            count = telemetry_repo.get_device_count("test_tenant")
            
            assert_equals(count, 2, "Should return unique device count")
    
    def test_get_device_count_permission_denied(self, telemetry_repo):
        """Test device count with permission denied error."""
        query_mock = Mock()
        query_mock.select.return_value.stream.side_effect = PermissionDenied("Permission denied")
        telemetry_repo.collection.where.return_value.select.return_value = query_mock
        
        count = telemetry_repo.get_device_count("test_tenant")
        
        assert_equals(count, 0, "Should return 0 on permission denied")
    
    def test_get_device_count_exception(self, telemetry_repo):
        """Test device count with general exception."""
        query_mock = Mock()
        query_mock.select.return_value.stream.side_effect = Exception("Test error")
        telemetry_repo.collection.where.return_value.select.return_value = query_mock
        
        count = telemetry_repo.get_device_count("test_tenant")
        
        assert_equals(count, 0, "Should return 0 on exception")
