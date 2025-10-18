"""Base classes and interfaces for Firestore data access layer."""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, TypeVar, Generic
from dataclasses import dataclass
from datetime import datetime
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

logger = logging.getLogger(__name__)

# Type variables for generic repository pattern
T = TypeVar('T')
K = TypeVar('K')


@dataclass
class QueryOptions:
    """Options for query operations."""
    limit: int = 100
    offset: Optional[str] = None  # For pagination
    order_by: Optional[str] = None
    order_direction: str = "DESCENDING"
    filters: Optional[Dict[str, Any]] = None


@dataclass
class PaginatedResult(Generic[T]):
    """Paginated query result."""
    items: List[T]
    total_count: Optional[int] = None
    has_more: bool = False
    next_offset: Optional[str] = None


@dataclass
class OperationResult(Generic[T]):
    """Result of a database operation."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


class FirestoreError(Exception):
    """Base exception for Firestore operations."""
    
    def __init__(self, message: str, error_code: str = "FIRESTORE_ERROR", original_error: Optional[Exception] = None):
        super().__init__(message)
        self.error_code = error_code
        self.original_error = original_error


class PermissionError(FirestoreError):
    """Permission denied error."""
    
    def __init__(self, message: str = "Permission denied", original_error: Optional[Exception] = None):
        super().__init__(message, "PERMISSION_DENIED", original_error)


class NotFoundError(FirestoreError):
    """Resource not found error."""
    
    def __init__(self, message: str = "Resource not found", original_error: Optional[Exception] = None):
        super().__init__(message, "NOT_FOUND", original_error)


class ValidationError(FirestoreError):
    """Data validation error."""
    
    def __init__(self, message: str = "Validation failed", original_error: Optional[Exception] = None):
        super().__init__(message, "VALIDATION_ERROR", original_error)


class BaseRepository(ABC, Generic[T, K]):
    """Base repository interface for Firestore operations."""
    
    def __init__(self, client: firestore.Client, collection_name: str):
        """Initialize repository with Firestore client and collection name."""
        self.client = client
        self.collection = client.collection(collection_name)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    def create(self, entity: T) -> OperationResult[K]:
        """Create a new entity."""
        pass
    
    @abstractmethod
    def get_by_id(self, entity_id: K) -> OperationResult[T]:
        """Get entity by ID."""
        pass
    
    @abstractmethod
    def update(self, entity_id: K, updates: Dict[str, Any]) -> OperationResult[T]:
        """Update entity by ID."""
        pass
    
    @abstractmethod
    def delete(self, entity_id: K) -> OperationResult[bool]:
        """Delete entity by ID."""
        pass
    
    def _handle_firestore_error(self, operation: str, error: Exception) -> None:
        """Handle Firestore errors and convert to custom exceptions."""
        if isinstance(error, PermissionDenied):
            self.logger.error(f"Permission denied during {operation}: {error}")
            raise PermissionError(f"Permission denied during {operation}", error)
        elif isinstance(error, NotFound):
            self.logger.error(f"Resource not found during {operation}: {error}")
            raise NotFoundError(f"Resource not found during {operation}", error)
        else:
            self.logger.error(f"Unexpected error during {operation}: {error}")
            raise FirestoreError(f"Error during {operation}: {str(error)}", original_error=error)
    
    def _validate_required_fields(self, data: Dict[str, Any], required_fields: List[str]) -> None:
        """Validate that required fields are present."""
        missing_fields = [field for field in required_fields if field not in data or data[field] is None]
        if missing_fields:
            raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def _normalize_timestamp(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Normalize timestamp to both millis and UTC string."""
        if timestamp is None:
            timestamp = datetime.utcnow().timestamp()

        timestamp_ms = int(timestamp * 1000)
        utc_timestamp = datetime.fromtimestamp(timestamp).isoformat()

        return {
            'timestamp_ms': timestamp_ms,
            'utc_timestamp': utc_timestamp
        }
    
    def _apply_query_options(self, query: firestore.Query, options: QueryOptions) -> firestore.Query:
        """Apply query options to Firestore query."""
        # Apply filters
        if options.filters:
            for field, value in options.filters.items():
                if isinstance(value, tuple) and len(value) == 2:
                    # Handle range queries like ('>=', 123)
                    operator, val = value
                    query = query.where(field, operator, val)
                else:
                    # Handle equality queries
                    query = query.where(field, '==', value)
        
        # Apply ordering
        if options.order_by:
            direction = firestore.Query.ASCENDING if options.order_direction == "ASCENDING" else firestore.Query.DESCENDING
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


class TenantAwareRepository(BaseRepository[T, K]):
    """Repository with multi-tenant awareness."""
    
    def __init__(self, client: firestore.Client, collection_name: str):
        super().__init__(client, collection_name)
    
    def _enforce_tenant_isolation(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure tenant_id is present and consistent."""
        if 'tenant_id' not in data:
            data['tenant_id'] = tenant_id
        elif data['tenant_id'] != tenant_id:
            raise ValidationError(f"Tenant ID mismatch: expected {tenant_id}, got {data['tenant_id']}")
        
        return data
    
    def _validate_tenant_access(self, tenant_id: Optional[str], entity_tenant_id: str) -> None:
        """Validate that user has access to the tenant."""
        if tenant_id is None:
            raise ValidationError("Tenant ID is required")
        if entity_tenant_id != tenant_id:
            raise PermissionError(f"Access denied to tenant {entity_tenant_id}")


class TimestampedRepository(BaseRepository[T, K]):
    """Repository with automatic timestamp management."""
    
    def __init__(self, client: firestore.Client, collection_name: str):
        super().__init__(client, collection_name)
    
    def _add_timestamps(self, data: Dict[str, Any], include_updated: bool = True) -> Dict[str, Any]:
        """Add creation and update timestamps."""
        now = datetime.utcnow().timestamp()
        timestamps = self._normalize_timestamp(now)
        
        data.update(timestamps)
        
        if include_updated:
            data['updated_at'] = timestamps['timestamp_ms']
        
        return data


class CacheableRepository(BaseRepository[T, K]):
    """Repository with caching support."""
    
    def __init__(self, client: firestore.Client, collection_name: str, cache_ttl: int = 300):
        super().__init__(client, collection_name)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, tuple] = {}  # key -> (data, timestamp)
    
    def _get_from_cache(self, key: str) -> Optional[T]:
        """Get data from cache if not expired."""
        if key in self._cache:
            data, timestamp = self._cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return data
            else:
                del self._cache[key]
        return None
    
    def _set_cache(self, key: str, data: T) -> None:
        """Set data in cache."""
        self._cache[key] = (data, time.time())
    
    def _clear_cache(self, key_prefix: str = None) -> None:
        """Clear cache entries matching prefix."""
        if key_prefix:
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(key_prefix)]
            for key in keys_to_remove:
                del self._cache[key]
        else:
            self._cache.clear()


