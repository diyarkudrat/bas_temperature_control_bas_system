"""Tests for Base Repository classes and methods."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    BaseRepository, TenantAwareRepository, TimestampedRepository, CacheableRepository,
    QueryOptions, PaginatedResult, OperationResult,
    FirestoreError, PermissionError, NotFoundError, ValidationError
)
from tests.unit.firestore.mock import (
    MockUser as User,
    MockPermissionDenied, MockNotFound
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises

# Contract testing imports
from tests.contracts.base import BaseRepositoryProtocol
from tests.contracts.firestore import ContractValidator
from tests.utils.business_rules import BusinessRules


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestBaseRepository:
    """Test cases for BaseRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def mock_repo(self, mock_client):
        """Create mock repository instance."""
        class MockRepository(BaseRepository):
            def create(self, entity):
                return OperationResult(success=True, data="test_id")
            
            def get_by_id(self, entity_id):
                return OperationResult(success=True, data={"id": entity_id})
            
            def update(self, entity_id, updates):
                return OperationResult(success=True, data={"id": entity_id})
            
            def delete(self, entity_id):
                return OperationResult(success=True, data=True)
        
        return MockRepository(mock_client, 'test_collection')

    @pytest.fixture
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    def test_init(self, mock_client, mock_repo):
        """Test repository initialization."""
        repo = mock_repo
        assert repo.client == mock_client
        assert repo.collection == mock_client.collection.return_value
        assert_is_not_none(repo.logger, "Should have logger")
    
    def test_handle_firestore_error_permission_denied(self, mock_repo):
        """Test handling PermissionDenied error."""
        error = MockPermissionDenied("Permission denied")
        
        with assert_raises(PermissionError):
            mock_repo._handle_firestore_error("test operation", error)
    
    def test_handle_firestore_error_not_found(self, mock_repo):
        """Test handling NotFound error."""
        error = MockNotFound("Resource not found")
        
        with assert_raises(NotFoundError):
            mock_repo._handle_firestore_error("test operation", error)
    
    def test_handle_firestore_error_generic(self, mock_repo):
        """Test handling generic error."""
        error = Exception("Generic error")
        
        with assert_raises(FirestoreError):
            mock_repo._handle_firestore_error("test operation", error)
    
    def test_validate_required_fields_success(self, mock_repo):
        """Test successful required fields validation."""
        data = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }
        required_fields = ['field1', 'field2']
        
        # Should not raise exception
        mock_repo._validate_required_fields(data, required_fields)
    
    def test_validate_required_fields_missing(self, mock_repo):
        """Test required fields validation with missing fields."""
        data = {
            'field1': 'value1',
            'field2': None,  # Missing value
            'field3': 'value3'
        }
        required_fields = ['field1', 'field2', 'field4']  # field4 is missing, field2 is None
        
        with assert_raises(ValidationError) as exc_info:
            mock_repo._validate_required_fields(data, required_fields)
        
        assert_true('field2, field4' in str(exc_info.exception), "Should mention missing fields")
    
    def test_validate_required_fields_not_in_data(self, mock_repo):
        """Test required fields validation when field is not in data."""
        data = {
            'field1': 'value1'
        }
        required_fields = ['field1', 'field2']  # field2 is not in data
        
        with assert_raises(ValidationError) as exc_info:
            mock_repo._validate_required_fields(data, required_fields)
        
        assert_true('field2' in str(exc_info.exception), "Should mention missing field2")
    
    def test_normalize_timestamp_with_timestamp(self, mock_repo):
        """Test timestamp normalization with provided timestamp."""
        timestamp = 1640995200.0  # 2022-01-01 00:00:00 UTC
        
        result = mock_repo._normalize_timestamp(timestamp)
        
        assert_equals(result['timestamp_ms'], 1640995200000, "Should convert to milliseconds")
        assert_equals(result['utc_timestamp'], '2022-01-01T00:00:00+00:00', "Should format as UTC timestamp")
    
    def test_normalize_timestamp_without_timestamp(self, mock_repo):
        """Test timestamp normalization without provided timestamp."""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1640995200.0
            with patch('datetime.datetime') as mock_datetime:
                mock_datetime.fromtimestamp.return_value.isoformat.return_value = '2022-01-01T00:00:00+00:00'
                
                result = mock_repo._normalize_timestamp()
                
                assert_equals(result['timestamp_ms'], 1640995200000, "Should convert to milliseconds")
                assert_equals(result['utc_timestamp'], '2022-01-01T00:00:00+00:00', "Should format as UTC timestamp")
    
    def test_apply_query_options_filters_equality(self, mock_repo):
        """Test applying query options with equality filters."""
        options = QueryOptions(
            filters={
                'field1': 'value1',
                'field2': 'value2'
            }
        )
        
        mock_query = Mock()
        mock_query.where.return_value = mock_query
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        # Should call where() for each filter
        assert_equals(mock_query.where.call_count, 2, "Should call where() for each filter")
        mock_query.where.assert_any_call('field1', '==', 'value1')
        mock_query.where.assert_any_call('field2', '==', 'value2')
    
    def test_apply_query_options_filters_range(self, mock_repo):
        """Test applying query options with range filters."""
        options = QueryOptions(
            filters={
                'timestamp': ('>=', 1640995200000),
                'price': ('<=', 100.0)
            }
        )
        
        mock_query = Mock()
        mock_query.where.return_value = mock_query
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        # Should call where() for each filter
        assert_equals(mock_query.where.call_count, 2, "Should call where() for each filter")
        mock_query.where.assert_any_call('timestamp', '>=', 1640995200000)
        mock_query.where.assert_any_call('price', '<=', 100.0)
    
    def test_apply_query_options_ordering(self, mock_repo):
        """Test applying query options with ordering."""
        options = QueryOptions(
            order_by='timestamp',
            order_direction='ASCENDING'
        )
        
        mock_query = Mock()
        mock_query.order_by.return_value = mock_query
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        mock_query.order_by.assert_called_once_with('timestamp', direction='ASCENDING')
    
    def test_apply_query_options_limit(self, mock_repo):
        """Test applying query options with limit."""
        options = QueryOptions(limit=50)
        
        mock_query = Mock()
        mock_query.limit.return_value = mock_query
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        mock_query.limit.assert_called_once_with(50)
    
    def test_apply_query_options_offset(self, mock_repo):
        """Test applying query options with offset."""
        options = QueryOptions(offset='last_doc_id')
        
        mock_query = Mock()
        mock_query.start_after.return_value = mock_query
        
        # Mock the document and its get() method
        mock_doc = Mock()
        mock_doc.exists = True
        mock_repo.collection.document.return_value.get.return_value = mock_doc
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        mock_query.start_after.assert_called_once_with(mock_doc)
    
    def test_apply_query_options_complex(self, mock_repo):
        """Test applying query options with multiple options."""
        options = QueryOptions(
            filters={'status': 'active', 'score': ('>=', 80)},
            order_by='created_at',
            order_direction='DESCENDING',
            limit=25,
            offset='doc_123'
        )
        
        mock_query = Mock()
        mock_query.where.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.start_after.return_value = mock_query
        
        # Mock the document and its get() method
        mock_doc = Mock()
        mock_doc.exists = True
        mock_repo.collection.document.return_value.get.return_value = mock_doc
        
        result = mock_repo._apply_query_options(mock_query, options)
        
        # Verify all methods were called
        assert_equals(mock_query.where.call_count, 2, "Should call where() for each filter")
        mock_query.order_by.assert_called_once_with('created_at', direction='DESCENDING')
        mock_query.limit.assert_called_once_with(25)
        mock_query.start_after.assert_called_once_with(mock_doc)


@pytest.mark.auth
@pytest.mark.unit
class TestTenantAwareRepository:
    """Test cases for TenantAwareRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def mock_tenant_repo(self, mock_client):
        """Create mock tenant-aware repository instance."""
        class MockTenantRepository(TenantAwareRepository):
            def create(self, entity):
                return OperationResult(success=True, data="test_id")
            
            def get_by_id(self, entity_id):
                return OperationResult(success=True, data={"id": entity_id})
            
            def update(self, entity_id, updates):
                return OperationResult(success=True, data={"id": entity_id})
            
            def delete(self, entity_id):
                return OperationResult(success=True, data=True)
        
        return MockTenantRepository(mock_client, 'test_collection')
    
    def test_enforce_tenant_isolation_success(self, mock_tenant_repo):
        """Test successful tenant isolation enforcement."""
        data = {
            'tenant_id': 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b',
            'field1': 'value1',
            'field2': 'value2'
        }
        
        result = mock_tenant_repo._enforce_tenant_isolation('e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', data)
        
        assert_equals(result['tenant_id'], 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', "Should preserve tenant_id")
        assert_equals(result['field1'], 'value1', "Should preserve other fields")
        assert_equals(result['field2'], 'value2', "Should preserve other fields")
    
    def test_enforce_tenant_isolation_override(self, mock_tenant_repo):
        """Test tenant isolation enforcement with tenant override."""
        data = {
            'tenant_id': 'wrong_tenant',  # Different from provided tenant
            'field1': 'value1'
        }
        
        result = mock_tenant_repo._enforce_tenant_isolation('e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', data)
        
        assert_equals(result['tenant_id'], 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', "Should override tenant_id")
        assert_equals(result['field1'], 'value1', "Should preserve other fields")
    
    def test_enforce_tenant_isolation_add_tenant(self, mock_tenant_repo):
        """Test tenant isolation enforcement when tenant_id is missing."""
        data = {
            'field1': 'value1',
            'field2': 'value2'
        }
        
        result = mock_tenant_repo._enforce_tenant_isolation('e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', data)
        
        assert_equals(result['tenant_id'], 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', "Should add tenant_id")
        assert_equals(result['field1'], 'value1', "Should preserve other fields")
        assert_equals(result['field2'], 'value2', "Should preserve other fields")
    
    def test_validate_tenant_access_success(self, mock_tenant_repo):
        """Test successful tenant access validation."""
        # Should not raise exception for valid tenant access
        mock_tenant_repo._validate_tenant_access('e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b')
    
    def test_validate_tenant_access_violation(self, mock_tenant_repo):
        """Test tenant access validation with violation."""
        with assert_raises(PermissionError) as exc_info:
            mock_tenant_repo._validate_tenant_access('e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b', 'tenant_456')
        
        assert_true('tenant access violation' in str(exc_info.exception).lower(), "Should mention tenant violation")
    
    def test_validate_tenant_access_none_tenant(self, mock_tenant_repo):
        """Test tenant access validation with None tenant."""
        with assert_raises(ValidationError) as exc_info:
            mock_tenant_repo._validate_tenant_access(None, 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b')
        
        assert_true('tenant id is required' in str(exc_info.exception).lower(), "Should mention tenant ID is required")


@pytest.mark.auth
@pytest.mark.unit
class TestTimestampedRepository:
    """Test cases for TimestampedRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def mock_timestamped_repo(self, mock_client):
        """Create mock timestamped repository instance."""
        class MockTimestampedRepository(TimestampedRepository):
            def create(self, entity):
                return OperationResult(success=True, data="test_id")
            
            def get_by_id(self, entity_id):
                return OperationResult(success=True, data={"id": entity_id})
            
            def update(self, entity_id, updates):
                return OperationResult(success=True, data={"id": entity_id})
            
            def delete(self, entity_id):
                return OperationResult(success=True, data=True)
        
        return MockTimestampedRepository(mock_client, 'test_collection')
    
    def test_add_timestamps_create_only(self, mock_timestamped_repo):
        """Test adding timestamps for create operation."""
        data = {
            'field1': 'value1',
            'field2': 'value2'
        }
        
        with patch.object(mock_timestamped_repo, '_normalize_timestamp') as mock_normalize:
            mock_normalize.return_value = {
                'timestamp_ms': 1640995200000,
                'utc_timestamp': '2022-01-01T00:00:00Z'
            }
            
            result = mock_timestamped_repo._add_timestamps(data)
            
            assert_equals(result['field1'], 'value1', "Should preserve original fields")
            assert_equals(result['field2'], 'value2', "Should preserve original fields")
            assert_equals(result['created_at'], 1640995200000, "Should add created_at")
            assert_equals(result['updated_at'], 1640995200000, "Should add updated_at")
            assert_equals(result['timestamp_ms'], 1640995200000, "Should add timestamp_ms")
            assert_equals(result['utc_timestamp'], '2022-01-01T00:00:00Z', "Should add utc_timestamp")
    
    def test_add_timestamps_with_update(self, mock_timestamped_repo):
        """Test adding timestamps for update operation."""
        data = {
            'field1': 'value1',
            'field2': 'value2'
        }
        
        with patch.object(mock_timestamped_repo, '_normalize_timestamp') as mock_normalize:
            mock_normalize.return_value = {
                'timestamp_ms': 1640995200000,
                'utc_timestamp': '2022-01-01T00:00:00Z'
            }
            
            result = mock_timestamped_repo._add_timestamps(data, include_updated=True)
            
            assert_equals(result['field1'], 'value1', "Should preserve original fields")
            assert_equals(result['field2'], 'value2', "Should preserve original fields")
            assert_equals(result['created_at'], 1640995200000, "Should add created_at")
            assert_equals(result['updated_at'], 1640995200000, "Should add updated_at")
            assert_equals(result['timestamp_ms'], 1640995200000, "Should add timestamp_ms")
            assert_equals(result['utc_timestamp'], '2022-01-01T00:00:00Z', "Should add utc_timestamp")
    
    def test_add_timestamps_preserve_existing(self, mock_timestamped_repo):
        """Test adding timestamps preserves existing timestamp fields."""
        data = {
            'field1': 'value1',
            'created_at': 1640995000000,  # Existing timestamp
            'timestamp_ms': 1640995000000  # Existing timestamp
        }
        
        with patch.object(mock_timestamped_repo, '_normalize_timestamp') as mock_normalize:
            mock_normalize.return_value = {
                'timestamp_ms': 1640995200000,
                'utc_timestamp': '2022-01-01T00:00:00Z'
            }
            
            result = mock_timestamped_repo._add_timestamps(data)
            
            assert_equals(result['field1'], 'value1', "Should preserve original fields")
            assert_equals(result['created_at'], 1640995000000, "Should preserve existing created_at")
            assert_equals(result['timestamp_ms'], 1640995000000, "Should preserve existing timestamp_ms")
            assert_equals(result['updated_at'], 1640995200000, "Should add new updated_at")
            assert_equals(result['utc_timestamp'], '2022-01-01T00:00:00Z', "Should add utc_timestamp")


@pytest.mark.auth
@pytest.mark.unit
class TestCacheableRepository:
    """Test cases for CacheableRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def mock_cacheable_repo(self, mock_client):
        """Create mock cacheable repository instance."""
        class MockCacheableRepository(CacheableRepository):
            def create(self, entity):
                return OperationResult(success=True, data="test_id")
            
            def get_by_id(self, entity_id):
                return OperationResult(success=True, data={"id": entity_id})
            
            def update(self, entity_id, updates):
                return OperationResult(success=True, data={"id": entity_id})
            
            def delete(self, entity_id):
                return OperationResult(success=True, data=True)
        
        return MockCacheableRepository(mock_client, 'test_collection')
    
    def test_get_from_cache_hit(self, mock_cacheable_repo):
        """Test cache hit scenario."""
        cache_key = 'test_key'
        cached_value = {'id': 'test_id', 'data': 'test_data'}
        
        # Mock cache with hit
        mock_cacheable_repo._cache = {cache_key: cached_value}
        
        result = mock_cacheable_repo._get_from_cache(cache_key)
        
        assert_equals(result, cached_value, "Should return cached value")
    
    def test_get_from_cache_miss(self, mock_cacheable_repo):
        """Test cache miss scenario."""
        cache_key = 'test_key'
        
        # Empty cache
        mock_cacheable_repo._cache = {}
        
        result = mock_cacheable_repo._get_from_cache(cache_key)
        
        assert_is_none(result, "Should return None for cache miss")
    
    def test_set_cache(self, mock_cacheable_repo):
        """Test setting cache value."""
        cache_key = 'test_key'
        value = {'id': 'test_id', 'data': 'test_data'}
        
        # Initialize cache
        mock_cacheable_repo._cache = {}
        
        mock_cacheable_repo._set_cache(cache_key, value)
        
        assert_equals(mock_cacheable_repo._cache[cache_key], value, "Should store value in cache")
    
    def test_set_cache_overwrite(self, mock_cacheable_repo):
        """Test overwriting cache value."""
        cache_key = 'test_key'
        old_value = {'id': 'old_id'}
        new_value = {'id': 'new_id', 'data': 'new_data'}
        
        # Initialize cache with old value
        mock_cacheable_repo._cache = {cache_key: old_value}
        
        mock_cacheable_repo._set_cache(cache_key, new_value)
        
        assert_equals(mock_cacheable_repo._cache[cache_key], new_value, "Should overwrite cache value")
    
    def test_clear_cache(self, mock_cacheable_repo):
        """Test clearing cache."""
        # Initialize cache with data
        mock_cacheable_repo._cache = {
            'key1': {'data': 'value1'},
            'key2': {'data': 'value2'},
            'key3': {'data': 'value3'}
        }
        
        mock_cacheable_repo._clear_cache()
        
        assert_equals(len(mock_cacheable_repo._cache), 0, "Should clear all cache entries")
    
    def test_clear_cache_specific_key(self, mock_cacheable_repo):
        """Test clearing specific cache key."""
        cache_key = 'key2'
        
        # Initialize cache with data
        mock_cacheable_repo._cache = {
            'key1': {'data': 'value1'},
            'key2': {'data': 'value2'},
            'key3': {'data': 'value3'}
        }
        
        mock_cacheable_repo._clear_cache(cache_key)
        
        assert_equals(len(mock_cacheable_repo._cache), 2, "Should remove only specified key")
        assert_true('key2' not in mock_cacheable_repo._cache, "Should remove specified key")
        assert_true('key1' in mock_cacheable_repo._cache, "Should preserve other keys")
        assert_true('key3' in mock_cacheable_repo._cache, "Should preserve other keys")
    
    def test_cache_operations_integration(self, mock_cacheable_repo):
        """Test integrated cache operations."""
        cache_key = 'test_key'
        value = {'id': 'test_id', 'data': 'test_data'}
        
        # Test set -> get -> clear cycle
        mock_cacheable_repo._set_cache(cache_key, value)
        retrieved = mock_cacheable_repo._get_from_cache(cache_key)
        assert_equals(retrieved, value, "Should retrieve set value")
        
        mock_cacheable_repo._clear_cache(cache_key)
        retrieved = mock_cacheable_repo._get_from_cache(cache_key)
        assert_is_none(retrieved, "Should return None after clearing specific key")
    
    def test_cache_multiple_keys(self, mock_cacheable_repo):
        """Test cache operations with multiple keys."""
        key1 = 'key1'
        key2 = 'key2'
        value1 = {'id': 'id1'}
        value2 = {'id': 'id2'}
        
        # Set multiple values
        mock_cacheable_repo._set_cache(key1, value1)
        mock_cacheable_repo._set_cache(key2, value2)
        
        # Retrieve multiple values
        retrieved1 = mock_cacheable_repo._get_from_cache(key1)
        retrieved2 = mock_cacheable_repo._get_from_cache(key2)
        
        assert_equals(retrieved1, value1, "Should retrieve first value")
        assert_equals(retrieved2, value2, "Should retrieve second value")
        
        # Clear one key
        mock_cacheable_repo._clear_cache(key1)
        
        retrieved1 = mock_cacheable_repo._get_from_cache(key1)
        retrieved2 = mock_cacheable_repo._get_from_cache(key2)
        
        assert_is_none(retrieved1, "Should return None for cleared key")
        assert_equals(retrieved2, value2, "Should still retrieve second value")


@pytest.mark.auth
@pytest.mark.unit
class TestDataClasses:
    """Test cases for data classes."""
    
    def test_query_options_defaults(self):
        """Test QueryOptions default values."""
        options = QueryOptions()
        
        assert_equals(options.limit, 100, "Should have default limit")
        assert_is_none(options.offset, "Should have None offset")
        assert_is_none(options.order_by, "Should have None order_by")
        assert_equals(options.order_direction, "DESCENDING", "Should have default order direction")
        assert_is_none(options.filters, "Should have None filters")
    
    def test_query_options_custom(self):
        """Test QueryOptions with custom values."""
        filters = {'status': 'active', 'score': ('>=', 80)}
        
        options = QueryOptions(
            limit=50,
            offset='doc_123',
            order_by='created_at',
            order_direction='ASCENDING',
            filters=filters
        )
        
        assert_equals(options.limit, 50, "Should set custom limit")
        assert_equals(options.offset, 'doc_123', "Should set custom offset")
        assert_equals(options.order_by, 'created_at', "Should set custom order_by")
        assert_equals(options.order_direction, 'ASCENDING', "Should set custom order direction")
        assert_equals(options.filters, filters, "Should set custom filters")
    
    def test_paginated_result_defaults(self):
        """Test PaginatedResult default values."""
        items = [{'id': '1'}, {'id': '2'}]
        
        result = PaginatedResult(items=items)
        
        assert_equals(result.items, items, "Should set items")
        assert_is_none(result.total_count, "Should have None total_count")
        assert_false(result.has_more, "Should have False has_more")
        assert_is_none(result.next_offset, "Should have None next_offset")
    
    def test_paginated_result_custom(self):
        """Test PaginatedResult with custom values."""
        items = [{'id': '1'}, {'id': '2'}]
        
        result = PaginatedResult(
            items=items,
            total_count=100,
            has_more=True,
            next_offset='doc_456'
        )
        
        assert_equals(result.items, items, "Should set items")
        assert_equals(result.total_count, 100, "Should set total_count")
        assert_true(result.has_more, "Should set has_more")
        assert_equals(result.next_offset, 'doc_456', "Should set next_offset")
    
    def test_operation_result_success(self):
        """Test OperationResult for successful operation."""
        data = {'id': 'test_id', 'name': 'test_name'}
        
        result = OperationResult(success=True, data=data)
        
        assert_true(result.success, "Should indicate success")
        assert_equals(result.data, data, "Should return data")
        assert_is_none(result.error, "Should have None error")
        assert_is_none(result.error_code, "Should have None error_code")
    
    def test_operation_result_failure(self):
        """Test OperationResult for failed operation."""
        result = OperationResult(
            success=False,
            error="Resource not found",
            error_code="NOT_FOUND"
        )
        
        assert_false(result.success, "Should indicate failure")
        assert_is_none(result.data, "Should have None data")
        assert_equals(result.error, "Resource not found", "Should return error message")
        assert_equals(result.error_code, "NOT_FOUND", "Should return error code")
    
    def test_firestore_error_defaults(self):
        """Test FirestoreError default values."""
        error = FirestoreError("Test error")
        
        assert_equals(str(error), "Test error", "Should return error message")
        assert_equals(error.error_code, "FIRESTORE_ERROR", "Should have default error code")
        assert_is_none(error.original_error, "Should have None original error")
    
    def test_firestore_error_custom(self):
        """Test FirestoreError with custom values."""
        original_error = Exception("Original error")
        
        error = FirestoreError(
            message="Test error",
            error_code="CUSTOM_ERROR",
            original_error=original_error
        )
        
        assert_equals(str(error), "Test error", "Should return error message")
        assert_equals(error.error_code, "CUSTOM_ERROR", "Should set custom error code")
        assert_equals(error.original_error, original_error, "Should set original error")
    
    def test_permission_error(self):
        """Test PermissionError."""
        original_error = Exception("Permission denied")
        
        error = PermissionError("Access denied", original_error)
        
        assert_equals(str(error), "Access denied", "Should return error message")
        assert_equals(error.error_code, "PERMISSION_DENIED", "Should set error code")
        assert_equals(error.original_error, original_error, "Should set original error")
    
    def test_not_found_error(self):
        """Test NotFoundError."""
        original_error = Exception("Not found")
        
        error = NotFoundError("Resource not found", original_error)
        
        assert_equals(str(error), "Resource not found", "Should return error message")
        assert_equals(error.error_code, "NOT_FOUND", "Should set error code")
        assert_equals(error.original_error, original_error, "Should set original error")
    
    def test_validation_error(self):
        """Test ValidationError."""
        original_error = Exception("Validation failed")

        error = ValidationError("Invalid data", original_error)

        assert_equals(str(error), "Invalid data", "Should return error message")
        assert_equals(error.error_code, "VALIDATION_ERROR", "Should set error code")
        assert_equals(error.original_error, original_error, "Should set original error")

    # Contract-based validation tests
    def test_contract_validation_create_operation(self, contract_validator):
        """Test contract validation for create operations."""
        # Test valid entity data
        entity_data = {
            'id': 'test_id',
            'name': 'Test Entity',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'created_at_ms': int(time.time() * 1000)
        }

        # Should validate successfully
        validation_result = contract_validator.validate_create_operation(
            entity_data,
            'entity',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid, f"Valid entity data should pass validation: {validation_result.violations}")

    def test_contract_validation_query_operation(self, contract_validator):
        """Test contract validation for query operations."""
        from tests.contracts.base import QueryOptions

        # Test valid query
        query_options = QueryOptions(
            filters={
                'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                'status': 'active'
            },
            limit=50,
            order_by='created_at_ms',
            order_direction='DESCENDING'
        )

        validation_result = contract_validator.validate_query_operation(
            query_options, 'entity', tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6', user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid, f"Valid query should pass validation: {validation_result.violations}")

    def test_contract_violation_tenant_isolation(self, contract_validator):
        """Test contract violation for tenant isolation."""
        # Test query without tenant isolation (should violate contract)
        invalid_options = QueryOptions(
            filters={
                'status': 'active'
                # Missing tenant_id
            },
            limit=50
        )

        validation_result = contract_validator.validate_query_operation(
            invalid_options, 'entity', tenant_id='k3l4m5n6-o7p8-4q9r-0s1t-2u3v4w5x6y7z', user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_false(validation_result.valid, "Query without tenant isolation should fail validation")
        assert_true(any("tenant" in violation.lower() or "isolation" in violation.lower()
                       for violation in validation_result.violations), "Should mention tenant or isolation")

    def test_business_rules_validation(self, business_rules):
        """Test business rules validation."""
        # Test valid auth check
        auth_result = business_rules.auth_check(
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            permissions=['read_data']
        )
        assert_true(auth_result['valid'], f"Valid auth should pass: {auth_result['violations']}")

        # Test TTL enforcement
        ttl_result = business_rules.ttl_enforce(
            created_at_ms=int(time.time() * 1000) - (30 * 24 * 60 * 60 * 1000),  # 30 days ago
            ttl_days=90
        )
        assert_true(ttl_result['valid'], f"Valid TTL should pass: {ttl_result['violations']}")
        assert_false(ttl_result['is_expired'], "Should not be expired")

    def test_contract_validator_business_rules_integration(self, contract_validator, business_rules):
        """Test contract validator integration with business rules."""
        # Test that contract validator uses business rules internally
        entity_data = {
            'id': 'test_id',
            'name': 'Test Entity',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6'
        }

        # This should use business rules internally
        validation_result = contract_validator.validate_business_rules(
            'auth_check',
            {
                'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
                'permissions': ['create_entity']
            }
        )
        assert_true(validation_result.valid, f"Auth check should pass: {validation_result.violations}")


# ======================= Server base.py coverage tests =======================
from adapters.db.firestore.base import (
    BaseRepository as SBaseRepository,
    TenantAwareRepository as STenantAwareRepository,
    TimestampedRepository as STimestampedRepository,
    CacheableRepository as SCacheableRepository,
    QueryOptions as SQueryOptions,
    FirestoreError as SFirestoreError,
    PermissionError as SPermissionError,
    NotFoundError as SNotFoundError,
    ValidationError as SValidationError,
)
from google.api_core.exceptions import NotFound as GNotFound, PermissionDenied as GPermissionDenied
from google.cloud import firestore as gcf


@pytest.mark.auth
@pytest.mark.unit
class TestServerBaseRepository:
    """Coverage for server/services/firestore/base.py BaseRepository paths."""

    @pytest.fixture
    def s_client(self):
        client = Mock()
        client.collection.return_value = Mock()
        return client

    @pytest.fixture
    def s_repo(self, s_client):
        class _Repo(SBaseRepository):
            def create(self, entity):
                return OperationResult(success=True, data="id")

            def get_by_id(self, entity_id):
                return OperationResult(success=True, data={"id": entity_id})

            def update(self, entity_id, updates):
                return OperationResult(success=True, data={"id": entity_id, **updates})

            def delete(self, entity_id):
                return OperationResult(success=True, data=True)

        return _Repo(s_client, "collection")

    def test_server_handle_firestore_error_permission_denied(self, s_repo):
        with assert_raises(SPermissionError):
            s_repo._handle_firestore_error("op", GPermissionDenied("denied"))

    def test_server_handle_firestore_error_not_found(self, s_repo):
        with assert_raises(SNotFoundError):
            s_repo._handle_firestore_error("op", GNotFound("missing"))

    def test_server_handle_firestore_error_generic(self, s_repo):
        with assert_raises(SFirestoreError):
            s_repo._handle_firestore_error("op", Exception("boom"))

    def test_server_validate_required_fields_paths(self, s_repo):
        s_repo._validate_required_fields({"a": 1, "b": 2}, ["a"])  # no raise
        with assert_raises(SValidationError):
            s_repo._validate_required_fields({"a": 1, "b": None}, ["a", "b", "c"])  # b None, c missing

    def test_server_normalize_timestamp_with_timestamp(self, s_repo):
        ts = 1640995200.0
        result = s_repo._normalize_timestamp(ts)
        assert_equals(result["timestamp_ms"], 1640995200000, "ms conversion")
        assert_equals(result["utc_timestamp"], datetime.fromtimestamp(ts).isoformat(), "local isoformat")

    def test_server_normalize_timestamp_without_timestamp(self, s_repo):
        with patch("adapters.db.firestore.base.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1640995200.0
            mock_iso_obj = Mock()
            mock_iso_obj.isoformat.return_value = "2022-01-01T00:00:00"
            mock_dt.fromtimestamp.return_value = mock_iso_obj
            result = s_repo._normalize_timestamp()
            assert_equals(result["timestamp_ms"], 1640995200000, "ms now")
            assert_equals(result["utc_timestamp"], "2022-01-01T00:00:00", "iso now")

    def test_server_apply_query_options_filters_and_order(self, s_repo):
        opts = SQueryOptions(
            filters={"f1": "v1", "age": (">=", 10)},
            order_by="created",
            order_direction="ASCENDING",
            limit=5,
        )
        q = Mock()
        q.where.return_value = q
        q.order_by.return_value = q
        q.limit.return_value = q
        res = s_repo._apply_query_options(q, opts)
        assert_equals(q.where.call_count, 2, "two filters")
        q.order_by.assert_called_once()
        # verify direction constant used
        _, kwargs = q.order_by.call_args
        assert_equals(kwargs.get("direction"), gcf.Query.ASCENDING, "ascending const")
        q.limit.assert_called_once_with(5)
        assert_equals(res, q, "chain returned")

    def test_server_apply_query_options_offset_valid_and_invalid(self, s_repo):
        q = Mock()
        q.start_after.return_value = q
        q.limit.return_value = q

        # valid offset path
        doc = Mock()
        doc.exists = True
        s_repo.collection.document.return_value.get.return_value = doc
        s_repo._apply_query_options(q, SQueryOptions(offset="doc1"))
        q.start_after.assert_called_once_with(doc)

        # invalid offset path (exception)
        q.start_after.reset_mock()
        s_repo.collection.document.return_value.get.side_effect = Exception("bad")
        s_repo._apply_query_options(q, SQueryOptions(offset="bad"))
        q.start_after.assert_not_called()

    def test_server_apply_query_options_descending(self, s_repo):
        q = Mock()
        q.order_by.return_value = q
        q.limit.return_value = q
        opts = SQueryOptions(order_by="created", order_direction="DESCENDING", limit=1)
        res = s_repo._apply_query_options(q, opts)
        _, kwargs = q.order_by.call_args
        assert_equals(kwargs.get("direction"), gcf.Query.DESCENDING, "descending const")
        q.limit.assert_called_once_with(1)
        assert_equals(res, q, "chain returned")

    def test_server_apply_query_options_offset_doc_not_exists(self, s_repo):
        q = Mock()
        q.start_after.return_value = q
        q.limit.return_value = q
        doc = Mock()
        doc.exists = False
        s_repo.collection.document.return_value.get.return_value = doc
        s_repo._apply_query_options(q, SQueryOptions(offset="doc2", limit=2))
        q.start_after.assert_not_called()
        q.limit.assert_called_once_with(2)


@pytest.mark.auth
@pytest.mark.unit
class TestServerTenantAwareRepository:
    @pytest.fixture
    def s_client(self):
        client = Mock()
        client.collection.return_value = Mock()
        return client

    @pytest.fixture
    def repo(self, s_client):
        class _Repo(STenantAwareRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")

            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})

            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})

            def delete(self, i):
                return OperationResult(success=True, data=True)

        return _Repo(s_client, "c")

    def test_enforce_tenant_isolation_paths(self, repo):
        # add when missing
        out = repo._enforce_tenant_isolation("t1", {"x": 1})
        assert_equals(out["tenant_id"], "t1", "added tenant")
        # ok when same
        out = repo._enforce_tenant_isolation("t1", {"tenant_id": "t1"})
        assert_equals(out["tenant_id"], "t1", "preserved")
        # mismatch raises
        with assert_raises(SValidationError):
            repo._enforce_tenant_isolation("t1", {"tenant_id": "t2"})

    def test_validate_tenant_access_paths(self, repo):
        # success
        repo._validate_tenant_access("t1", "t1")
        # none -> validation
        with assert_raises(SValidationError):
            repo._validate_tenant_access(None, "t1")
        # mismatch -> permission
        with assert_raises(SPermissionError):
            repo._validate_tenant_access("t1", "t2")


@pytest.mark.auth
@pytest.mark.unit
class TestServerTimestampedRepository:
    @pytest.fixture
    def s_client(self):
        client = Mock()
        client.collection.return_value = Mock()
        return client

    @pytest.fixture
    def repo(self, s_client):
        class _Repo(STimestampedRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")

            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})

            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})

            def delete(self, i):
                return OperationResult(success=True, data=True)

        return _Repo(s_client, "c")

    def test_add_timestamps_includes_updated(self, repo):
        with patch("adapters.db.firestore.base.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1640995200.0
            mock_iso_obj = Mock()
            mock_iso_obj.isoformat.return_value = "2022-01-01T00:00:00"
            mock_dt.fromtimestamp.return_value = mock_iso_obj
            out = repo._add_timestamps({"a": 1})
            assert_equals(out["timestamp_ms"], 1640995200000, "ms added")
            assert_equals(out["utc_timestamp"], "2022-01-01T00:00:00", "iso added")
            assert_equals(out["updated_at"], 1640995200000, "updated_at added")

    def test_add_timestamps_without_updated(self, repo):
        with patch("adapters.db.firestore.base.datetime") as mock_dt:
            mock_dt.utcnow.return_value.timestamp.return_value = 1640995200.0
            mock_iso_obj = Mock()
            mock_iso_obj.isoformat.return_value = "2022-01-01T00:00:00"
            mock_dt.fromtimestamp.return_value = mock_iso_obj
            out = repo._add_timestamps({"a": 1}, include_updated=False)
            assert_true("updated_at" not in out, "no updated_at when disabled")


@pytest.mark.auth
@pytest.mark.unit
class TestServerCacheableRepository:
    @pytest.fixture
    def s_client(self):
        client = Mock()
        client.collection.return_value = Mock()
        return client

    def test_cache_hit_and_set(self, s_client):
        class _Repo(SCacheableRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")
            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})
            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})
            def delete(self, i):
                return OperationResult(success=True, data=True)
        repo = _Repo(s_client, "c")
        key = "k"
        val = {"v": 1}
        repo._set_cache(key, val)
        got = repo._get_from_cache(key)
        assert_equals(got, val, "cache returns set value within ttl")

    def test_cache_expired_entry(self, s_client):
        class _Repo(SCacheableRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")
            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})
            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})
            def delete(self, i):
                return OperationResult(success=True, data=True)
        repo = _Repo(s_client, "c", cache_ttl=0)
        key = "k"
        val = {"v": 1}
        # Insert stale by directly setting past timestamp
        repo._cache[key] = (val, time.time() - 10)
        got = repo._get_from_cache(key)
        assert_is_none(got, "expired should be evicted and return None")
        assert_true(key not in repo._cache, "expired entry removed")

    def test_clear_cache_prefix_and_all(self, s_client):
        class _Repo(SCacheableRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")
            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})
            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})
            def delete(self, i):
                return OperationResult(success=True, data=True)
        repo = _Repo(s_client, "c")
        repo._cache = {
            "user:1": ({"v": 1}, time.time()),
            "user:2": ({"v": 2}, time.time()),
            "dev:1": ({"v": 3}, time.time()),
        }
        repo._clear_cache("user:")
        assert_true("user:1" not in repo._cache and "user:2" not in repo._cache, "prefix cleared")
        assert_true("dev:1" in repo._cache, "others kept")
        repo._clear_cache()
        assert_equals(len(repo._cache), 0, "all cleared")

    def test_cache_miss_returns_none(self, s_client):
        class _Repo(SCacheableRepository):
            def create(self, e):
                return OperationResult(success=True, data="id")
            def get_by_id(self, i):
                return OperationResult(success=True, data={"id": i})
            def update(self, i, u):
                return OperationResult(success=True, data={"id": i, **u})
            def delete(self, i):
                return OperationResult(success=True, data=True)
        repo = _Repo(s_client, "c")
        missing = repo._get_from_cache("missing")
        assert_is_none(missing, "miss returns None")
