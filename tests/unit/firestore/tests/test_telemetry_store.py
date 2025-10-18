"""Tests for TelemetryRepository with contract-based validation."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

# Legacy mock imports (to be phased out)
from tests.unit.firestore.mock import (
    TelemetryRepository, MockTelemetryRecord as TelemetryRecord, create_mock_telemetry_record as create_telemetry_record,
    OperationResult, QueryOptions, PaginatedResult, FirestoreError, PermissionError, ValidationError,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound
)

# Contract testing imports
from tests.contracts.base import TelemetryStoreProtocol
from tests.contracts.firestore import ContractValidator, ContractEnforcer
from tests.contracts.mocks import MockFirestoreClient
from tests.utils.business_rules import BusinessRules
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
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
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    @pytest.fixture
    def contract_enforcer(self):
        """Provide contract enforcer for decoupled validation."""
        return ContractEnforcer()

    @pytest.fixture
    def mock_firestore_client(self):
        """Provide mock Firestore client aligned with real adapters."""
        return MockFirestoreClient()

    @pytest.fixture
    def sample_telemetry(self):
        """Create sample telemetry record for testing."""
        return TelemetryRecord(
            tenant_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            device_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
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

    @pytest.fixture
    def valid_telemetry_data(self) -> Dict[str, Any]:
        """Provide valid telemetry data for testing."""
        return {
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'device_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'timestamp_ms': int(time.time() * 1000),
            'utc_timestamp': datetime.utcnow().isoformat() + '+00:00',
            'temp_tenths': 230,
            'setpoint_tenths': 240,
            'deadband_tenths': 10,
            'cool_active': False,
            'heat_active': True,
            'state': 'HEATING',
            'sensor_ok': True
        }
    
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
            device_id="f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c",
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
    
    def test_query_recent_for_device_success(self, telemetry_repo, sample_telemetry, contract_enforcer):
        """Test successful recent telemetry query for device with contract validation."""
        options = QueryOptions(limit=10)

        # Validate query options against contract before execution
        query_options = QueryOptions(
            filters={'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6', 'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c'},
            order_by='timestamp_ms',
            limit=10
        )

        validation_result = contract_enforcer.validator.validate_query_operation(
            query_options, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid,
                   f"Query validation should pass: {validation_result.violations}")

        # Create mock result directly
        expected_result = PaginatedResult(
            items=[sample_telemetry, sample_telemetry],
            has_more=False,
            next_offset="doc2"
        )

        with patch.object(telemetry_repo, '_execute_query') as mock_execute_query:
            mock_execute_query.return_value = expected_result

            result = telemetry_repo.query_recent_for_device("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", options)

            assert_is_instance(result, PaginatedResult, "Should return PaginatedResult")
            assert_equals(len(result.items), 2, "Should return 2 items")
            assert_equals(result.next_offset, "doc2", "Should set next_offset")
            assert_false(result.has_more, "Should not have more items")
    
    def test_query_recent_for_device_permission_denied(self, telemetry_repo, contract_enforcer):
        """Test recent query with permission denied error using contract validation."""
        options = QueryOptions(limit=10)

        # First validate that query options are correct according to contract
        query_options = QueryOptions(
            filters={'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6', 'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c'},
            order_by='timestamp_ms',
            limit=10
        )

        validation_result = contract_enforcer.validator.validate_query_operation(
            query_options, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        # Even though query is valid, we expect permission error during execution
        assert_true(validation_result.valid,
                   f"Query validation should pass before permission check: {validation_result.violations}")

        with patch.object(telemetry_repo, '_apply_query_options') as mock_apply_options:
            mock_apply_options.return_value.stream.side_effect = PermissionDenied("Permission denied")

            with assert_raises(PermissionError):
                telemetry_repo.query_recent_for_device("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", options)
    
    def test_query_time_window_success(self, telemetry_repo, sample_telemetry, contract_enforcer):
        """Test successful time window query with contract validation."""
        start_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        end_time = int(time.time() * 1000)
        options = QueryOptions(limit=100)

        # Validate complex query options against contract
        query_options = QueryOptions(
            filters={
                'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c',
                'timestamp_ms': ('>=', start_time),
                'timestamp_ms': ('<=', end_time)
            },
            order_by='timestamp_ms',
            limit=100
        )

        validation_result = contract_enforcer.validator.validate_query_operation(
            query_options, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid,
                   f"Time window query validation should pass: {validation_result.violations}")

        # Create mock result directly
        expected_result = PaginatedResult(
            items=[sample_telemetry],
            has_more=False,
            next_offset=None
        )

        with patch.object(telemetry_repo, '_execute_query') as mock_execute_query:
            mock_execute_query.return_value = expected_result

            result = telemetry_repo.query_time_window("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", start_time, end_time, options)

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
                telemetry_repo.query_time_window("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", start_time, end_time, options)
    
    def test_get_device_statistics_success(self, telemetry_repo, sample_telemetry):
        """Test successful device statistics generation."""
        # Create multiple telemetry records for statistics
        telemetry_records = [
            TelemetryRecord(
                tenant_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                device_id="f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c",
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
                tenant_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                device_id="f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c",
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
                tenant_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                device_id="f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c",
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
            
            stats = telemetry_repo.get_device_statistics("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 24)
            
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
            
            stats = telemetry_repo.get_device_statistics("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 24)
            
            assert_equals(stats['total_records'], 0, "Should return zero records")
            assert_equals(stats['avg_temperature'], 0, "Should return zero average")
            assert_equals(stats['uptime_percentage'], 0, "Should return zero uptime")
    
    def test_get_device_statistics_permission_denied(self, telemetry_repo):
        """Test device statistics with permission denied error."""
        with patch.object(telemetry_repo, 'get_statistics_for_device') as mock_get_stats:
            mock_get_stats.side_effect = PermissionError("Permission denied")
            
            # The method catches exceptions and returns default stats, so test that behavior
            stats = telemetry_repo.get_device_statistics("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 24)
            
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
            
            result = telemetry_repo.add_telemetry("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", data)
            
            assert_true(result, "Legacy add_telemetry should succeed")
            mock_create.assert_called_once()
    
    def test_add_telemetry_legacy_failure(self, telemetry_repo):
        """Test legacy add_telemetry method with failure."""
        data = {'temp_tenths': 230}
        
        with patch.object(telemetry_repo, 'create') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = telemetry_repo.add_telemetry("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", data)
            
            assert_false(result, "Legacy add_telemetry should fail")
    
    def test_query_recent_legacy_success(self, telemetry_repo, sample_telemetry):
        """Test legacy query_recent method."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.return_value = PaginatedResult(items=[sample_telemetry], has_more=False)
            
            result = telemetry_repo.query_recent("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 100)
            
            assert_equals(len(result), 1, "Should return 1 item")
            assert_is_instance(result[0], dict, "Should return dict format")
    
    def test_query_recent_legacy_failure(self, telemetry_repo):
        """Test legacy query_recent method with failure."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.side_effect = Exception("Test error")
            
            result = telemetry_repo.query_recent("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 100)
            
            assert_equals(result, [], "Should return empty list on failure")
    
    def test_query_window_legacy_success(self, telemetry_repo, sample_telemetry):
        """Test legacy query_window method."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        
        with patch.object(telemetry_repo, 'query_by_timestamp_range') as mock_query:
            mock_query.return_value = PaginatedResult(items=[sample_telemetry], has_more=False)
            
            result = telemetry_repo.query_window("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", start_time, end_time, 1000)
            
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
            
            result = telemetry_repo.query_recent_paginated("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 100)
            
            assert_equals(len(result['data']), 1, "Should return 1 item in data")
            assert_equals(result['last_doc_id'], "next_doc_id", "Should return next doc ID")
            assert_true(result['has_more'], "Should indicate more data available")
    
    def test_query_recent_paginated_legacy_failure(self, telemetry_repo):
        """Test legacy query_recent_paginated method with failure."""
        with patch.object(telemetry_repo, 'query_recent_for_device') as mock_query:
            mock_query.side_effect = Exception("Test error")
            
            result = telemetry_repo.query_recent_paginated("3fa85f64-5717-4562-b3fc-2c963f66afa6", "f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c", 100)
            
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
            
            count = telemetry_repo.get_device_count("3fa85f64-5717-4562-b3fc-2c963f66afa6")
            
            assert_equals(count, 2, "Should return unique device count")
    
    def test_get_device_count_permission_denied(self, telemetry_repo):
        """Test device count with permission denied error."""
        query_mock = Mock()
        query_mock.select.return_value.stream.side_effect = PermissionDenied("Permission denied")
        telemetry_repo.collection.where.return_value.select.return_value = query_mock
        
        count = telemetry_repo.get_device_count("3fa85f64-5717-4562-b3fc-2c963f66afa6")
        
        assert_equals(count, 0, "Should return 0 on permission denied")
    
    def test_get_device_count_exception(self, telemetry_repo):
        """Test device count with general exception."""
        query_mock = Mock()
        query_mock.select.return_value.stream.side_effect = Exception("Test error")
        telemetry_repo.collection.where.return_value.select.return_value = query_mock

        count = telemetry_repo.get_device_count("3fa85f64-5717-4562-b3fc-2c963f66afa6")

        assert_equals(count, 0, "Should return 0 on exception")

    def test_contract_validation_create_telemetry(self, telemetry_repo, contract_validator, business_rules, valid_telemetry_data):
        """Test contract validation for telemetry creation."""
        # Validate telemetry data structure against contract
        validation_result = contract_validator.validate_create_operation(
            valid_telemetry_data,
            'telemetry',
            tenant_id=valid_telemetry_data['tenant_id'],
            user_id=None  # Telemetry doesn't require user_id
        )
        assert_true(validation_result.valid, f"Contract validation failed: {validation_result.violations}")

    def test_contract_violation_invalid_temperature(self, contract_validator, valid_telemetry_data):
        """Test contract violation with invalid temperature data."""
        invalid_data = valid_telemetry_data.copy()
        invalid_data['temp_tenths'] = -100  # Invalid negative temperature

        validation_result = contract_validator.validate_create_operation(
            invalid_data,
            'telemetry',
            tenant_id=valid_telemetry_data['tenant_id']
        )

        assert_false(validation_result.valid, "Invalid telemetry data should fail validation")
        assert_true(len(validation_result.violations) > 0, "Should have validation violations")

    def test_business_rules_telemetry_validation(self, business_rules, valid_telemetry_data):
        """Test business rules validation for telemetry."""
        # Test valid telemetry data
        result = business_rules.telemetry_validation_check(
            tenant_id=valid_telemetry_data['tenant_id'],
            device_id=valid_telemetry_data['device_id'],
            temp_tenths=valid_telemetry_data['temp_tenths'],
            sensor_ok=valid_telemetry_data['sensor_ok']
        )

        assert_true(result['valid'], f"Telemetry validation failed: {result['violations']}")

    def test_query_contract_validation(self, telemetry_repo, contract_validator, valid_telemetry_data):
        """Test contract validation for query operations."""
        from tests.contracts.base import QueryOptions

        tenant_id = valid_telemetry_data['tenant_id']
        device_id = valid_telemetry_data['device_id']

        # Validate query filters against contract
        query_options = QueryOptions(
            filters={
                'tenant_id': tenant_id,
                'device_id': device_id,
                'timestamp_ms': ('>=', int(time.time() * 1000) - 3600000)  # Last hour
            },
            limit=100
        )

        # Should validate successfully
        validation_result = contract_validator.validate_query_operation(
            query_options, 'telemetry', tenant_id=tenant_id
        )
        assert_true(validation_result.valid, f"Valid query should pass validation: {validation_result.violations}")

        # Test query without tenant isolation (should violate contract)
        invalid_options = QueryOptions(
            filters={
                'device_id': device_id
                # Missing tenant_id
            },
            limit=100
        )

        invalid_result = contract_validator.validate_query_operation(
            invalid_options, 'telemetry', tenant_id=tenant_id
        )
        assert_false(invalid_result.valid, "Query without tenant isolation should fail validation")

    def test_negative_path_assertions_decoupled(self, contract_enforcer):
        """Test negative path assertions using contract enforcer instead of chained queries."""
        # Test invalid query patterns that should be caught by contract validation

        # Test 1: Query with too many inequality filters (should fail)
        invalid_query_options = QueryOptions(
            filters={
                'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c',
                'timestamp_ms': ('>', 1000000),
                'temp_tenths': ('<', 300),
                'sensor_ok': True  # This makes it too many inequalities
            },
            limit=50
        )

        validation_result = contract_enforcer.validator.validate_query_operation(
            invalid_query_options, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_false(validation_result.valid, "Query with multiple inequalities should fail")

        # Test 2: Query exceeding limit bounds
        oversized_query = QueryOptions(
            filters={'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6', 'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c'},
            limit=1500  # Exceeds max limit
        )

        limit_validation = contract_enforcer.validator.validate_query_operation(
            oversized_query, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_false(limit_validation.valid, "Query exceeding limit should fail")

        # Test 3: Valid query should pass (positive assertion)
        valid_query = QueryOptions(
            filters={'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6', 'device_id': 'f6a7b8c9-d0e1-4f5a-9b0c-6d7e8f9a0b1c'},
            order_by='timestamp_ms',
            limit=100
        )

        valid_result = contract_enforcer.validator.validate_query_operation(
            valid_query, 'telemetry', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(valid_result.valid, "Valid query should pass contract validation")


# ---------------------------
# Server repository test suite
# ---------------------------

import types

from server.services.firestore.telemetry_store import TelemetryRepository as ServerTelemetryRepository
from server.services.firestore.models import TelemetryRecord as ServerTelemetryRecord, create_telemetry_record as server_create_telemetry_record
from server.services.firestore.base import OperationResult as ServerOperationResult, PaginatedResult as ServerPaginatedResult, PermissionError as ServerPermissionError
from google.api_core.exceptions import PermissionDenied as GAPermissionDenied


@pytest.mark.unit
class TestServerTelemetryRepository:
    @pytest.fixture
    def server_client(self):
        client = Mock()
        client.collection.return_value = Mock()
        return client

    @pytest.fixture
    def server_repo(self, server_client):
        return ServerTelemetryRepository(server_client)

    @pytest.fixture
    def server_sample(self):
        return ServerTelemetryRecord(
            tenant_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            device_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
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

    def test__execute_query_success(self, server_repo):
        doc1 = Mock(); doc1.id = "d1"; doc1.to_dict.return_value = {
            'tenant_id': 't', 'device_id': 'a', 'timestamp_ms': 1, 'utc_timestamp': 'u',
            'temp_tenths': 1, 'setpoint_tenths': 2, 'deadband_tenths': 1, 'cool_active': False,
            'heat_active': True, 'state': 'S', 'sensor_ok': True
        }
        doc2 = Mock(); doc2.id = "d2"; doc2.to_dict.return_value = doc1.to_dict.return_value
        query = Mock(); query.stream.return_value = [doc1, doc2]

        result = server_repo._execute_query(query, server_create_telemetry_record)

        assert_is_instance(result, ServerPaginatedResult)
        assert_equals(len(result.items), 2, "Should convert documents to records")
        assert_false(result.has_more, "Should not have more when <100 results")
        assert_is_none(result.next_offset, "No next offset when has_more False")

    def test__execute_query_exception(self, server_repo):
        query = Mock(); query.stream.side_effect = Exception("boom")
        result = server_repo._execute_query(query, server_create_telemetry_record)
        assert_is_instance(result, ServerPaginatedResult)
        assert_equals(len(result.items), 0, "Returns empty on exception")
        assert_false(result.has_more, "No more on exception")

    def test_get_statistics_for_device_empty(self, server_repo):
        query = Mock(); query.stream.return_value = []
        with patch.object(server_repo, '_apply_query_options') as mock_apply:
            mock_apply.return_value = query
            out = server_repo.get_statistics_for_device('t', 'd', 0, 1)
        assert_true(out.success)
        assert_equals(out.data['record_count'], 0, "Empty stats when no records")

    def test_get_statistics_for_device_computed(self, server_repo):
        # Two good sensor records and one failure
        def mk_doc(temp, setpt, cool, heat, ok, idv):
            d = Mock(); d.id = idv
            d.to_dict.return_value = {
                'tenant_id': 't', 'device_id': 'd', 'timestamp_ms': 1, 'utc_timestamp': 'u',
                'temp_tenths': temp, 'setpoint_tenths': setpt, 'deadband_tenths': 1,
                'cool_active': cool, 'heat_active': heat, 'state': 'S', 'sensor_ok': ok
            }
            return d
        docs = [mk_doc(220, 240, False, True, True, 'a'), mk_doc(240, 240, True, False, True, 'b'), mk_doc(0, 240, False, False, False, 'c')]
        query = Mock(); query.stream.return_value = docs
        with patch.object(server_repo, '_apply_query_options') as mock_apply:
            mock_apply.return_value = query
            out = server_repo.get_statistics_for_device('t', 'd', 0, 1)
        assert_true(out.success)
        stats = out.data
        assert_equals(stats['record_count'], 3, "Counts all records")
        assert_equals(stats['temp_min'], 220, "Min temp excludes failed sensor 0")
        assert_equals(stats['temp_max'], 240, "Max temp computed")
        assert_equals(stats['temp_avg'], 230, "Average of good temps 220 and 240")
        assert_equals(stats['sensor_failures'], 1, "One failed sensor")

    def test_get_device_statistics_default_when_result_failure(self, server_repo):
        with patch.object(server_repo, 'get_statistics_for_device') as mock_stats:
            mock_stats.return_value = ServerOperationResult(success=False, error="x")
            stats = server_repo.get_device_statistics('t', 'd', 24)
        assert_equals(stats['total_records'], 0)
        assert_equals(stats['avg_temperature'], 0)
        assert_equals(stats['uptime_percentage'], 0)

    def test_get_device_statistics_permission_denied_raises(self, server_repo):
        with patch.object(server_repo, 'get_statistics_for_device') as mock_stats:
            mock_stats.side_effect = GAPermissionDenied("denied")
            with assert_raises(ServerPermissionError):
                server_repo.get_device_statistics('t', 'd', 24)

    def test_query_recent_for_device_permission_denied_maps(self, server_repo):
        with patch.object(server_repo, '_apply_query_options') as mock_apply:
            mock_apply.side_effect = GAPermissionDenied("denied")
            with assert_raises(ServerPermissionError):
                server_repo.query_recent_for_device('t', 'd')

    def test_query_time_window_permission_denied_maps(self, server_repo):
        with patch.object(server_repo, '_apply_query_options') as mock_apply:
            mock_apply.side_effect = GAPermissionDenied("denied")
            with assert_raises(ServerPermissionError):
                server_repo.query_time_window('t', 'd', 0, 1)

    def test_query_by_timestamp_range_alias(self, server_repo):
        with patch.object(server_repo, 'query_time_window') as mock_q:
            mock_q.return_value = ServerPaginatedResult(items=[], has_more=False)
            out = server_repo.query_by_timestamp_range('t', 'd', 0, 1)
            mock_q.assert_called_once_with('t', 'd', 0, 1, None)
            assert_is_instance(out, ServerPaginatedResult)
