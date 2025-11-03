"""Base classes and interfaces for Firestore data access layer."""

import logging
import time
import threading
import os
import random
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, TypeVar, Generic, Protocol, Callable
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied


logger = logging.getLogger(__name__)

# Type variables for generic repository pattern
T = TypeVar('T')
K = TypeVar('K')


@dataclass
class QueryOptions:
    """Options for query operations."""

    limit: int = 100 # Limit
    offset: Optional[str] = None  # For pagination
    order_by: Optional[str] = None # Order by
    order_direction: str = "DESCENDING" # Order direction
    filters: Optional[Dict[str, Any]] = None # Filters


@dataclass
class PaginatedResult(Generic[T]):
    """Paginated query result."""

    items: List[T] # Items
    total_count: Optional[int] = None # Total count
    has_more: bool = False # Has more
    next_offset: Optional[str] = None # Next offset


@dataclass
class OperationResult(Generic[T]):
    """Result of a database operation."""

    success: bool # Success
    data: Optional[T] = None # Data
    error: Optional[str] = None # Error
    error_code: Optional[str] = None # Error code


class FirestoreError(Exception):
    """Base exception for Firestore operations."""
    
    def __init__(self, message: str, error_code: str = "FIRESTORE_ERROR", original_error: Optional[Exception] = None):
        """Initialize the Firestore error."""

        super().__init__(message)
        self.error_code = error_code # Error code
        self.original_error = original_error # Original error


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


class FirestoreClientBoundary(Protocol):
    """Boundary-first protocol for Firestore-like clients used by repositories."""

    def collection(self, name: str) -> Any: ...
    def collections(self) -> Any: ...


@dataclass
class RetryPolicy:
    """Retry/backoff and time budget settings for repository operations."""

    op_timeout_s: float = 0.05  # 50 ms soft budget per op
    max_retries: int = 2        # at most 2 retries (3 attempts total)
    backoff_base_s: float = 0.01 # Backoff base
    backoff_factor: float = 2.0 # Backoff factor
    backoff_cap_s: float = 0.05 # Backoff cap


class _CircuitBreaker:
    """Lightweight circuit breaker for Firestore paths (module-local)."""

    def __init__(self, failure_threshold: int = 5, window_s: float = 30.0, reset_timeout_s: float = 15.0) -> None:
        """Initialize the circuit breaker."""

        self._failure_threshold = max(1, failure_threshold) # Failure threshold
        self._window_s = window_s # Window size
        self._reset_timeout_s = reset_timeout_s # Reset timeout
        self._failures = deque()  # type: ignore[var-annotated] # Failures
        self._open_until: float = 0.0 # Open until
        self._lock = threading.RLock() # Lock

    def allow_call(self) -> bool:
        """Allow a call to the circuit breaker."""

        with self._lock:
            now = time.monotonic()

            if now < self._open_until:
                return False

            cutoff = now - self._window_s

            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()

            return True

    def on_success(self) -> None:
        """On success, reset the circuit breaker."""

        with self._lock:
            self._open_until = 0.0
            self._failures.clear()

    def on_failure(self) -> None:
        """On failure, increment the failure count."""
        with self._lock:
            now = time.monotonic()

            # Ensure non-decreasing timestamps to keep deque ordered
            if self._failures:
                last = self._failures[-1]

                if now < last:
                    now = last

            self._failures.append(now)

            cutoff = now - self._window_s
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()

            if len(self._failures) >= self._failure_threshold:
                self._open_until = now + self._reset_timeout_s


class BaseRepository(ABC, Generic[T, K]):
    """Base repository interface for Firestore operations."""
    
    def __init__(self, client: FirestoreClientBoundary, collection_name: str, *, retry_policy: Optional[RetryPolicy] = None, breaker: Optional["_CircuitBreaker"] = None):
        """Initialize repository with Firestore client and collection name."""

        self._client = client # Firestore client
        self._collection = client.collection(collection_name) # Collection
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}") # Logger
        # Initialize retry policy from environment overrides
        self._policy = retry_policy or RetryPolicy(
            op_timeout_s=float(os.getenv("FS_OP_TIMEOUT_S", "0.05")),
            max_retries=int(os.getenv("FS_MAX_RETRIES", "2")),
            backoff_base_s=float(os.getenv("FS_BACKOFF_BASE_S", "0.01")),
            backoff_factor=float(os.getenv("FS_BACKOFF_FACTOR", "2.0")),
            backoff_cap_s=float(os.getenv("FS_BACKOFF_CAP_S", "0.05")),
        ) # Retry policy
        # Circuit breaker to isolate persistent failures
        self._breaker = breaker or _CircuitBreaker(
            failure_threshold=int(os.getenv("FS_BREAKER_THRESHOLD", "5")),
            window_s=float(os.getenv("FS_BREAKER_WINDOW_S", "30")),
            reset_timeout_s=float(os.getenv("FS_BREAKER_RESET_S", "15")),
        ) # Circuit breaker

    @property
    def client(self) -> FirestoreClientBoundary:
        """Firestore client (read-only)."""

        return self._client

    @property
    def collection(self) -> Any:
        """Collection reference (read-only)."""

        return self._collection
    
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
            dt = datetime.now(timezone.utc)
        else:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        timestamp_ms = int(dt.timestamp() * 1000)
        utc_timestamp = dt.isoformat().replace('+00:00', 'Z')

        return {
            'timestamp_ms': timestamp_ms,
            'utc_timestamp': utc_timestamp
        }
    
    def _apply_query_options(self, query: Any, options: QueryOptions) -> Any:
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
                offset_doc = self._collection.document(options.offset).get()
                if offset_doc.exists:
                    query = query.start_after(offset_doc)
            except Exception as e:
                self.logger.warning(f"Invalid offset {options.offset}: {e}")
        
        # Apply limit
        query = query.limit(options.limit)
        
        return query
    
    # ------------------------------
    # Resilience helpers (optional for subclasses to use)
    # ------------------------------

    def _execute_with_retry(self, op_name: str, func: Callable[[], T]) -> T:
        """Execute func with bounded retries and soft time budget under a breaker.

        Subclasses may wrap Firestore calls with this to gain resilience. On
        budget exhaustion or repeated failures, the last exception is raised
        for the caller to handle via _handle_firestore_error.
        """

        # Short-circuit if breaker is open
        if not self._breaker.allow_call():
            raise FirestoreError(f"Breaker open for operation: {op_name}")

        start = time.monotonic()
        attempt = 0
        while True:
            try:
                result = func()
                self._breaker.on_success()

                return result
            except Exception as e:
                # If soft time budget exceeded, propagate immediately
                if (time.monotonic() - start) >= self._policy.op_timeout_s:
                    self._breaker.on_failure()
                    raise

                # If retries exhausted, propagate
                if attempt >= self._policy.max_retries:
                    self._breaker.on_failure()
                    raise

                # Sleep with exponential backoff + full jitter
                sleep_ceiling = min(
                    self._policy.backoff_cap_s,
                    self._policy.backoff_base_s * (self._policy.backoff_factor ** attempt),
                )

                time.sleep(random.uniform(0.0, max(0.0, sleep_ceiling)))
                attempt += 1


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
        
        dt = datetime.now(timezone.utc)
        timestamps = self._normalize_timestamp(dt.timestamp())
        
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

            if time.monotonic() - timestamp < self.cache_ttl:
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
