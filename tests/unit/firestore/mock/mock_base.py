"""Mock base classes and interfaces for Firestore data access layer."""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, TypeVar, Generic
from dataclasses import dataclass
import time
from unittest.mock import Mock

logger = logging.getLogger(__name__)

# Type variables for generic repository pattern
T = TypeVar('T')
K = TypeVar('K')


@dataclass
class MockQueryOptions:
    """Mock options for query operations."""
    limit: int = 100
    offset: Optional[str] = None  # For pagination
    order_by: Optional[str] = None
    order_direction: str = "DESCENDING"
    filters: Optional[Dict[str, Any]] = None


@dataclass
class MockPaginatedResult(Generic[T]):
    """Mock paginated query result."""
    items: List[T]
    total_count: Optional[int] = None
    has_more: bool = False
    next_offset: Optional[str] = None


@dataclass
class MockOperationResult(Generic[T]):
    """Mock result of a database operation."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


class MockFirestoreError(Exception):
    """Mock base exception for Firestore operations."""
    
    def __init__(self, message: str, error_code: str = "FIRESTORE_ERROR", original_error: Optional[Exception] = None):
        super().__init__(message)
        self.error_code = error_code
        self.original_error = original_error


class MockPermissionError(MockFirestoreError):
    """Mock permission denied error."""
    
    def __init__(self, message: str = "Permission denied", original_error: Optional[Exception] = None):
        super().__init__(message, "PERMISSION_DENIED", original_error)


class MockNotFoundError(MockFirestoreError):
    """Mock resource not found error."""
    
    def __init__(self, message: str = "Resource not found", original_error: Optional[Exception] = None):
        super().__init__(message, "NOT_FOUND", original_error)


class MockValidationError(MockFirestoreError):
    """Mock data validation error."""
    
    def __init__(self, message: str = "Validation failed", original_error: Optional[Exception] = None):
        super().__init__(message, "VALIDATION_ERROR", original_error)


class MockBaseRepository(ABC, Generic[T, K]):
    """Mock base repository interface for Firestore operations."""
    
    def __init__(self, client: Mock, collection_name: str):
        """Initialize repository with mock Firestore client and collection name."""
        self.client = client
        self.collection = client.collection(collection_name)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def create(self, entity: T) -> MockOperationResult[K]:
        """Create a new entity."""
        pass
    
    @abstractmethod
    def get_by_id(self, entity_id: K) -> MockOperationResult[T]:
        """Get entity by ID."""
        pass
    
    @abstractmethod
    def update(self, entity_id: K, updates: Dict[str, Any]) -> MockOperationResult[T]:
        """Update entity by ID."""
        pass
    
    @abstractmethod
    def delete(self, entity_id: K) -> MockOperationResult[bool]:
        """Delete entity by ID."""
        pass
    
    def _handle_firestore_error(self, operation: str, error: Exception) -> None:
        """Handle mock Firestore errors and convert to custom exceptions."""
        from .mock_exceptions import MockPermissionDenied, MockNotFound
        
        if isinstance(error, MockPermissionDenied):
            self.logger.error(f"Permission denied during {operation}: {error}")
            raise MockPermissionError(f"Permission denied during {operation}", error)
        elif isinstance(error, MockNotFound):
            self.logger.error(f"Resource not found during {operation}: {error}")
            raise MockNotFoundError(f"Resource not found during {operation}", error)
        elif isinstance(error, MockValidationError):
            self.logger.error(f"Validation error during {operation}: {error}")
            raise MockValidationError(f"Validation error during {operation}: {str(error)}")
        elif isinstance(error, MockPermissionError):
            # Re-raise MockPermissionError as-is
            raise error
        elif isinstance(error, MockNotFoundError):
            # Re-raise MockNotFoundError as-is
            raise error
        elif isinstance(error, MockValidationError):
            # Re-raise MockValidationError as-is
            raise error
        else:
            self.logger.error(f"Unexpected error during {operation}: {error}")
            raise MockFirestoreError(f"Error during {operation}: {str(error)}", original_error=error)
    
    def _handle_mock_firestore_error(self, operation: str, error: Exception) -> None:
        """Handle mock Firestore errors and convert to custom exceptions."""
        return self._handle_firestore_error(operation, error)
    
    def _validate_required_fields(self, data: Dict[str, Any], required_fields: List[str]) -> None:
        """Validate that required fields are present."""
        missing_fields = [field for field in required_fields if field not in data or data[field] is None]
        if missing_fields:
            raise MockValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def _normalize_timestamp(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Normalize timestamp to both millis and UTC string."""
        if timestamp is None:
            timestamp = time.time()
        
        timestamp_ms = int(timestamp * 1000)
        from datetime import datetime, timezone
        utc_timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        
        return {
            'timestamp_ms': timestamp_ms,
            'utc_timestamp': utc_timestamp
        }
    
    def _apply_query_options(self, query: Mock, options: MockQueryOptions) -> Mock:
        """Apply query options to mock Firestore query."""
        # Store the original stream method if it exists
        original_stream = getattr(query, 'stream', None)
        
        # Apply filters
        if options.filters:
            for field, value in options.filters.items():
                if isinstance(value, tuple) and len(value) == 2:
                    # Handle range queries like ('>=', 123)
                    operator, val = value
                    # Call where on the current query (preserves call tracking)
                    query = query.where(field, operator, val)
                else:
                    # Handle equality queries
                    query = query.where(field, '==', value)
        
        # Apply ordering
        if options.order_by:
            direction = "ASCENDING" if options.order_direction == "ASCENDING" else "DESCENDING"
            query = query.order_by(options.order_by, direction=direction)
        
        # Apply pagination
        if options.offset:
            try:
                offset_doc = self.collection.document(options.offset).get()
                if offset_doc.exists:
                    query = query.start_after(offset_doc)
            except Exception as e:
                self.logger.warning(f"Invalid offset {options.offset}: {e}")
        
        # Apply limit
        query = query.limit(options.limit)
        
        return query


class MockTenantAwareRepository(MockBaseRepository[T, K]):
    """Mock repository with multi-tenant awareness."""
    
    def __init__(self, client: Mock, collection_name: str):
        super().__init__(client, collection_name)
    
    def _enforce_tenant_isolation(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure tenant_id is present and consistent."""
        if 'tenant_id' not in data:
            data['tenant_id'] = tenant_id
        elif data['tenant_id'] != tenant_id:
            # Override tenant_id to match the provided tenant_id
            data['tenant_id'] = tenant_id
        
        return data
    
    def _validate_tenant_access(self, tenant_id: str, entity_tenant_id: str) -> None:
        """Validate that user has access to the tenant."""
        if tenant_id is None:
            raise MockValidationError("Tenant ID is required")
        if entity_tenant_id != tenant_id:
            raise MockPermissionError(f"Tenant access violation: requested {tenant_id}, found {entity_tenant_id}")


class MockTimestampedRepository(MockBaseRepository[T, K]):
    """Mock repository with automatic timestamp management."""
    
    def __init__(self, client: Mock, collection_name: str):
        super().__init__(client, collection_name)
    
    def _add_timestamps(self, data: Dict[str, Any], include_updated: bool = True) -> Dict[str, Any]:
        """Add creation and update timestamps."""
        now = time.time()
        timestamps = self._normalize_timestamp(now)
        
        # Preserve existing timestamps if they exist
        if 'timestamp_ms' not in data:
            data.update(timestamps)
        else:
            # Only add utc_timestamp if it doesn't exist
            if 'utc_timestamp' not in data:
                data['utc_timestamp'] = timestamps['utc_timestamp']
        
        # Add created_at if it doesn't exist
        if 'created_at' not in data:
            data['created_at'] = timestamps['timestamp_ms']
        
        if include_updated:
            data['updated_at'] = timestamps['timestamp_ms']
        
        return data


class MockCacheableRepository(MockBaseRepository[T, K]):
    """Mock repository with caching support."""
    
    def __init__(self, client: Mock, collection_name: str, cache_ttl: int = 300):
        super().__init__(client, collection_name)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Any] = {}  # key -> data (simplified for tests)
    
    def _get_from_cache(self, key: str) -> Optional[T]:
        """Get data from cache if not expired."""
        if key in self._cache:
            return self._cache[key]
        return None
    
    def _set_cache(self, key: str, data: T) -> None:
        """Set data in cache."""
        self._cache[key] = data
    
    def _clear_cache(self, key_prefix: str = None) -> None:
        """Clear cache entries matching prefix."""
        if key_prefix:
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(key_prefix)]
            for key in keys_to_remove:
                del self._cache[key]
        else:
            self._cache.clear()


class MockErrorMappingRegistry:
    """Mock error mapping registry for converting Firestore exceptions."""
    
    _mappings: Dict[type, callable] = {}
    
    @classmethod
    def register(cls, exception_type: type):
        """Register an error mapping."""
        def decorator(func):
            cls._mappings[exception_type] = func
            return func
        return decorator
    
    @classmethod
    def map_error(cls, error: Exception) -> Exception:
        """Map Firestore error to custom exception."""
        error_type = type(error)
        if error_type in cls._mappings:
            return cls._mappings[error_type](str(error), error)
        return MockFirestoreError(f"Unmapped error: {str(error)}", original_error=error)
    
    @classmethod
    def clear(cls):
        """Clear all mappings."""
        cls._mappings.clear()


class MockTenantTimestampedRepository(MockTenantAwareRepository[T, K], MockTimestampedRepository[T, K]):
    """Mock repository combining tenant awareness and timestamping."""
    
    def __init__(self, client: Mock, collection_name: str):
        super().__init__(client, collection_name)


# Create aliases for backward compatibility
QueryOptions = MockQueryOptions
PaginatedResult = MockPaginatedResult
OperationResult = MockOperationResult
FirestoreError = MockFirestoreError
PermissionError = MockPermissionError
NotFoundError = MockNotFoundError
ValidationError = MockValidationError
BaseRepository = MockBaseRepository
TenantAwareRepository = MockTenantAwareRepository
TimestampedRepository = MockTimestampedRepository
CacheableRepository = MockCacheableRepository
ErrorMappingRegistry = MockErrorMappingRegistry
