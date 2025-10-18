"""Optimized contract mocks with lazy initialization and validation."""

import time
import logging
from typing import Dict, Any, Optional, List, Type, Callable, TypeVar
from unittest.mock import Mock, MagicMock
from functools import lru_cache
from dataclasses import dataclass, field
import uuid

from .base import (
    OperationResult, PaginatedResult, QueryOptions
)
from .firestore import ContractEnforcer, ContractViolationError, ContractValidator
from ..utils.business_rules import BusinessRules

logger = logging.getLogger(__name__)

T = TypeVar('T')


# Local Firestore-like permission exception used in tests and mocks
class PermissionDenied(Exception):
    pass


@dataclass
class MockStoreConfig:
    """Configuration for mock store behavior."""
    collection_name: str
    tenant_id: Optional[str] = None
    enable_validation: bool = True
    enable_business_rules: bool = True
    lazy_init: bool = True
    max_cache_size: int = 1000


class ContractMockStore:
    """Base class for contract-compliant mock stores with lazy initialization."""

    def __init__(self, client: Mock, config: MockStoreConfig):
        """Initialize contract mock store."""
        self.client = client
        self.config = config
        self.collection = client.collection(config.collection_name)
        self._enforcer = ContractEnforcer() if config.enable_validation else None
        self._validator = ContractValidator() if config.enable_validation else None
        self._business_rules = BusinessRules() if config.enable_business_rules else None
        self._store: Dict[str, Dict[str, Any]] = {}
        self._initialized = False

    def _lazy_init(self):
        """Lazy initialization of store."""
        if not self._initialized and self.config.lazy_init:
            self._initialized = True
            logger.debug(f"Lazy initialized mock store for {self.config.collection_name}")

    def _validate_operation(self, operation: str, data: Dict[str, Any],
                          required_fields: Optional[List[str]] = None) -> None:
        """Validate operation against contract."""
        if not self._enforcer:
            return

        try:
            if operation == 'create':
                self._enforcer.enforce_create_contract(
                    data,
                    required_fields or [],
                    self.config.tenant_id,
                    user_id=(data.get('user_id') if isinstance(data, dict) else None) or (data.get('username') if isinstance(data, dict) else None),
                )
            elif operation == 'query':
                if not self._validator:
                    return
                # Build QueryOptions from dict-like data
                if isinstance(data, dict):
                    query_options = QueryOptions(filters=data)
                else:
                    query_options = QueryOptions()
                result = self._validator.validate_query_operation(
                    query_options,
                    entity_type=self.config.collection_name,
                    tenant_id=self.config.tenant_id,
                )
                if not result.valid:
                    raise ContractViolationError(f"Contract violations: {result.violations}")
            elif operation == 'delete':
                # For delete operations, data is typically just the ID
                if isinstance(data, str):
                    if not self._validator:
                        return
                    result = self._validator.validate_delete_operation(
                        entity_id=data,
                        entity_type=self.config.collection_name,
                        tenant_id=self.config.tenant_id,
                    )
                    if not result.valid:
                        raise ContractViolationError(f"Contract violations: {result.violations}")
        except ContractViolationError as e:
            logger.warning(f"Contract violation in {operation}: {e}")
            raise

    def _apply_business_rules(self, rule_name: str, **kwargs) -> Dict[str, Any]:
        """Apply business rules validation."""
        if not self._business_rules:
            return {'valid': True, 'violations': []}
        return getattr(self._business_rules, rule_name)(**kwargs)

    def _mock_operation_result(self, success: bool, data: Any = None,
                             error: str = None, error_code: str = None) -> OperationResult:
        """Create a mock operation result."""
        return OperationResult(success=success, data=data, error=error, error_code=error_code)

    def _mock_paginated_result(self, items: List[T], has_more: bool = False,
                             next_offset: Optional[str] = None) -> PaginatedResult[T]:
        """Create a mock paginated result."""
        return PaginatedResult(items=items, has_more=has_more, next_offset=next_offset)


class AuditStoreContractMock(ContractMockStore):
    """Contract-compliant mock for audit store operations."""

    # Mapping from audit event types to business rule operation names
    EVENT_TO_OPERATION_MAP = {
        'LOGIN_SUCCESS': 'login',
        'LOGIN_FAILURE': 'login',
        'LOGOUT': 'logout',
        'SESSION_CREATED': 'create_session',
        'SESSION_DESTROYED': 'delete_session',
        'PERMISSION_DENIED': 'data_access',
        'TENANT_VIOLATION': 'data_access',
        'SYSTEM_STARTUP': 'system_config_change',
        'USER_CREATED': 'create_user',
        'USER_DELETED': 'delete_user',
        'PASSWORD_CHANGED': 'update_password',
        'DEVICE_REGISTERED': 'device_registration',
        'DEVICE_REMOVED': 'device_removal',
    }

    def __init__(self, client: Mock, tenant_id: Optional[str] = None):
        config = MockStoreConfig(
            collection_name='audit',
            tenant_id=tenant_id,
            enable_validation=True,
            enable_business_rules=True
        )
        super().__init__(client, config)

    def log_event(self, event_type: str, user_id: Optional[str] = None, username: Optional[str] = None,
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None) -> bool:
        """Log audit event with contract validation."""
        self._lazy_init()

        current_time = int(time.time() * 1000)
        from datetime import datetime, timezone
        utc_timestamp = datetime.fromtimestamp(current_time / 1000, tz=timezone.utc).isoformat()

        audit_doc = {
            'timestamp_ms': current_time,
            'utc_timestamp': utc_timestamp,
            'event_type': event_type,
            'user_id': user_id,
            'username': username,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details or {},
            'tenant_id': tenant_id or self.config.tenant_id
        }

        # Validate against contract
        self._validate_operation('create', audit_doc, ['event_type', 'timestamp_ms', 'utc_timestamp'])

        # Apply business rules
        if self._business_rules:
            # Map audit event type to business rule operation name
            operation_name = self.EVENT_TO_OPERATION_MAP.get(event_type, event_type.lower())
            rule_result = self._apply_business_rules('audit_trail_check',
                                                   operation=operation_name,
                                                   user_id=user_id,
                                                   tenant_id=tenant_id or self.config.tenant_id)
            if not rule_result['valid']:
                logger.warning(f"Business rule violation for {event_type}: {rule_result['violations']}")
                return False

        # Store in mock
        doc_id = f"audit_{current_time}_{hash(str(audit_doc))}"
        self._store[doc_id] = audit_doc

        # Mock the Firestore call
        self.collection.add.return_value = (None, Mock(id=doc_id))

        logger.debug(f"Mock logged audit event: {event_type} for user {username}")
        return True

    def log_auth_success(self, username: str, ip_address: str, session_id: str,
                        tenant_id: Optional[str] = None) -> bool:
        """Log successful authentication."""
        return self.log_event(
            event_type='LOGIN_SUCCESS',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )

    def log_auth_failure(self, username: str, ip_address: str, failure_reason: str,
                        tenant_id: Optional[str] = None) -> bool:
        """Log failed authentication."""
        return self.log_event(
            event_type='LOGIN_FAILURE',
            username=username,
            ip_address=ip_address,
            details={'failure_reason': failure_reason},
            tenant_id=tenant_id
        )

    def query_events_by_user(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by user ID with contract validation."""
        self._lazy_init()

        # Validate query
        query_filters = {'user_id': user_id, 'tenant_id': self.config.tenant_id}
        self._validate_operation('query', query_filters)

        # Mock query results
        results = []
        for doc_id, data in list(self._store.items())[:limit]:
            if data.get('user_id') == user_id:
                result_data = data.copy()
                result_data['id'] = doc_id
                results.append(result_data)

        return results


class UserStoreContractMock(ContractMockStore):
    """Contract-compliant mock for user store operations."""

    def __init__(self, client: Mock, tenant_id: Optional[str] = None):
        config = MockStoreConfig(
            collection_name='users',
            tenant_id=tenant_id,
            enable_validation=True,
            enable_business_rules=True
        )
        super().__init__(client, config)

    def create(self, user_data: Dict[str, Any]) -> OperationResult[str]:
        """Create user with contract validation."""
        self._lazy_init()

        # Validate required fields
        # Align with tests: require username and password_hash; email optional
        required_fields = ['username', 'password_hash']
        self._validate_operation('create', user_data, required_fields)

        # Apply password policy rules
        if self._business_rules and 'hashed_password' in user_data:
            # For mock purposes, validate the field exists (actual password would be hashed)
            pass

        # Mock successful creation
        user_id = user_data.get('user_id') or str(uuid.uuid4())
        stored = user_data.copy()
        # Fill expected shapes used in tests
        stored.setdefault('user_id', user_id)
        stored.setdefault('hashed_password', user_data.get('password_hash') or user_data.get('hashed_password'))
        self._store[user_id] = stored

        return self._mock_operation_result(True, user_id)

    def get_by_id(self, user_id: str) -> OperationResult[Dict[str, Any]]:
        """Get user by ID."""
        self._lazy_init()

        if user_id in self._store:
            return self._mock_operation_result(True, self._store[user_id])

        return self._mock_operation_result(False, error="User not found",)

    def get_by_username(self, username: str, tenant_id: Optional[str] = None) -> OperationResult[Dict[str, Any]]:
        """Get user by username."""
        self._lazy_init()
        # First, try querying through the mocked Firestore chain so tests can patch .where().limit().stream()
        try:
            query = None
            try:
                query = self.collection.where('username', '==', username).limit(1)
            except Exception:
                query = None
            if query is not None:
                try:
                    docs = list(query.stream())
                    if docs:
                        doc = docs[0]
                        data = doc.to_dict()
                        if isinstance(data, dict):
                            data = {**data, 'id': getattr(doc, 'id', None)}
                        return self._mock_operation_result(True, data)
                except PermissionDenied:  # type: ignore[name-defined]
                    # Map Firestore-like permission exceptions to built-in PermissionError
                    raise PermissionError("Permission denied")
                except Exception:
                    # Fall through to in-memory search on any other mock setup issues
                    pass
            # Fallback to in-memory store
            for _, user_data in self._store.items():
                if user_data.get('username') == username:
                    return self._mock_operation_result(True, user_data)
            return self._mock_operation_result(False, error="User not found", error_code="NOT_FOUND")
        except PermissionDenied:  # type: ignore[name-defined]
            raise PermissionError("Permission denied")

    # Legacy convenience methods expected by tests
    def create_user(self, username: str, password_hash: str, salt: str, role: str) -> OperationResult[str]:
        user_data = {
            'username': username,
            'password_hash': password_hash,
            'salt': salt,
            'role': role,
            'email': f"{username}@example.com",
        }
        try:
            result = self.create(user_data)
            return result.data if result.success else None
        except Exception:
            return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        result = self.get_by_id(user_id)
        data = result.data if result.success else None
        if data is None:
            return None
        return data if isinstance(data, dict) else data.to_dict()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        result = self.get_by_username(username)
        data = result.data if result.success else None
        if data is None:
            return None
        return data if isinstance(data, dict) else data.to_dict()

    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        try:
            result = self.update(user_id, updates)
            return bool(result.success)
        except Exception:
            return False

    def delete_user(self, username: str) -> bool:
        # Legacy flow should call get_by_username then delete by returned user_id
        try:
            result = self.get_by_username(username)
            if not result.success or not result.data:
                return False
            user = result.data
            if isinstance(user, dict):
                user_id_val = user.get('user_id') or user.get('id')
            else:
                user_id_val = getattr(user, 'user_id', None) or getattr(user, 'id', None)
            if not user_id_val:
                uname = (user.get('username') if isinstance(user, dict) else getattr(user, 'username', None))
                if uname:
                    # Deterministically derive a UUID from username for stability in tests
                    user_id_val = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uname)))
                    if isinstance(user, dict):
                        user['user_id'] = user_id_val
                    else:
                        setattr(user, 'user_id', user_id_val)
                else:
                    return False
            return bool(self.delete(user_id_val).success)
        except Exception:
            return False

    def is_user_locked(self, username: str) -> bool:
        # Use repository method so tests can patch it
        result = self.get_by_username(username)
        if not result.success or not result.data:
            return False
        user = result.data
        locked_until = user.get('locked_until', 0) if isinstance(user, dict) else getattr(user, 'locked_until', 0)
        return isinstance(locked_until, int) and locked_until > int(time.time() * 1000)

    def update(self, user_id: str, updates: Dict[str, Any]) -> OperationResult[Dict[str, Any]]:
        """Update user by ID."""
        self._lazy_init()

        # Validate update operation
        self._validate_operation('update', updates)

        if user_id not in self._store:
            return self._mock_operation_result(False, error="User not found")

        # Apply updates
        self._store[user_id].update(updates)
        return self._mock_operation_result(True, self._store[user_id])

    def delete(self, user_id: str) -> OperationResult[bool]:
        """Delete user by ID."""
        self._lazy_init()

        if user_id in self._store:
            del self._store[user_id]
            return self._mock_operation_result(True, True)

        return self._mock_operation_result(False, error="User not found")

    def update_password(self, user_id: str, new_password_hash: str, new_salt: str, algorithm_params: Optional[Dict[str, Any]] = None) -> OperationResult[Dict[str, Any]]:
        """Update user password. Accept optional algorithm params and perform two updates."""
        # Record password history (no-op in mock storage, but simulates behavior)
        history_update = {
            'password_history_entry': {
                'changed_at_ms': int(time.time() * 1000),
                'algorithm': (algorithm_params or {}).get('algorithm') if isinstance(algorithm_params, dict) else None,
            }
        }
        first = self.update(user_id, history_update)
        if not first.success:
            return first
        updates = {
            'password_hash': new_password_hash,
            'salt': new_salt,
            'updated_at_ms': int(time.time() * 1000)
        }
        return self.update(user_id, updates)

    def update_last_login(self, user_id: str, ip_address: Optional[str] = None) -> OperationResult[Dict[str, Any]]:
        """Update user's last login information. IP optional for tests."""
        updates = {
            'last_login_ip': ip_address,
            'last_login_at_ms': int(time.time() * 1000),
            'updated_at_ms': int(time.time() * 1000)
        }
        return self.update(user_id, updates)

    # Additional methods used by legacy tests
    def authenticate_user(self, username: str, password_hash: str) -> OperationResult[Dict[str, Any]]:
        result = self.get_by_username(username)
        if not result.success:
            return OperationResult(success=False, error="User not found", error_code="USER_NOT_FOUND")
        user = result.data
        # Handle object with attributes or dict
        stored_hash = user.password_hash if hasattr(user, 'password_hash') else user.get('password_hash') or user.get('hashed_password')
        locked_until_val = getattr(user, 'locked_until', None) if not isinstance(user, dict) else user.get('locked_until')
        # Ensure user_id exists so patched methods see exact arg
        user_id_val = getattr(user, 'user_id', None) if not isinstance(user, dict) else user.get('user_id')
        if not user_id_val:
            name_for_uuid = getattr(user, 'username', None) if not isinstance(user, dict) else user.get('username')
            derived_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(name_for_uuid))) if name_for_uuid else str(uuid.uuid4())
            if isinstance(user, dict):
                user['user_id'] = derived_id
            else:
                setattr(user, 'user_id', derived_id)
            user_id_val = derived_id
        if isinstance(locked_until_val, int) and locked_until_val > int(time.time() * 1000):
            return OperationResult(success=False, error="Account locked", error_code="ACCOUNT_LOCKED")
        if stored_hash != password_hash:
            # increment failed attempts via method if available
            try:
                self.increment_failed_attempts(user_id_val)
            except Exception:
                pass
            return OperationResult(success=False, error="Invalid credentials", error_code="INVALID_CREDENTIALS")
        # success
        try:
            self.clear_failed_attempts(user_id_val)
        except Exception:
            pass
        return OperationResult(success=True, data=user)

    def increment_failed_attempts(self, user_id: str) -> OperationResult[None]:
        result = self.get_by_id(user_id)
        if not result.success:
            return OperationResult(success=False, error="User not found")
        # For dict or object
        if isinstance(result.data, dict):
            current = result.data.get('failed_attempts', 0)
        else:
            current = getattr(result.data, 'failed_attempts', 0)
        # Always route through update so tests can patch/observe the call
        return self.update(user_id, {'failed_attempts': current + 1})

    def clear_failed_attempts(self, user_id: str) -> OperationResult[None]:
        return self.update(user_id, {'failed_attempts': 0})

    def lock_user(self, user_id: str, lock_until_ms: int) -> OperationResult[None]:
        return self.update(user_id, {'locked_until': lock_until_ms})

    def _apply_query_options(self):
        return self.collection

    # Listing/query helpers expected by tests
    def list_users_by_role(self, role: str, options: QueryOptions) -> PaginatedResult:
        try:
            query = self._apply_query_options()
            stream = query.stream()
            items = []
            for doc in stream:
                data = doc.to_dict()
                # Return lightweight objects with attribute access and id to satisfy tests
                class _UserObj:
                    pass
                obj = _UserObj()
                if isinstance(data, dict):
                    for k, v in data.items():
                        setattr(obj, k, v)
                setattr(obj, 'id', getattr(doc, 'id', None))
                items.append(obj)
            return self._mock_paginated_result(items=items, has_more=False, next_offset=None)
        except PermissionDenied as e:  # type: ignore[name-defined]
            raise PermissionError("Permission denied")

    def deactivate_user(self, user_id: str) -> OperationResult[bool]:
        """Deactivate a user account."""
        updates = {
            'is_active': False,
            'updated_at_ms': int(time.time() * 1000)
        }
        result = self.update(user_id, updates)
        return OperationResult(success=result.success, data=result.success, error=result.error)


class DeviceStoreContractMock(ContractMockStore):
    """Contract-compliant mock for device store operations."""

    def __init__(self, client: Mock, tenant_id: Optional[str] = None):
        config = MockStoreConfig(
            collection_name='devices',
            tenant_id=tenant_id,
            enable_validation=True,
            enable_business_rules=True
        )
        super().__init__(client, config)

    def register_device(self, device_data: Dict[str, Any], tenant_id: str) -> OperationResult[str]:
        """Register device with validation."""
        self._lazy_init()

        # Ensure tenant isolation
        device_data['tenant_id'] = tenant_id
        self._validate_operation('create', device_data, ['device_id', 'serial_number'])

        device_id = f"device_{hash(device_data['serial_number'])}"
        self._store[device_id] = device_data.copy()

        return self._mock_operation_result(True, device_id)


class SessionStoreContractMock(ContractMockStore):
    """Contract-compliant mock for session store operations."""

    def __init__(self, client: Mock, tenant_id: Optional[str] = None):
        config = MockStoreConfig(
            collection_name='sessions',
            tenant_id=tenant_id,
            enable_validation=True,
            enable_business_rules=True
        )
        super().__init__(client, config)

    def create(self, session_data: Dict[str, Any]) -> OperationResult[str]:
        """Create session with contract validation."""
        self._lazy_init()

        # Validate session data
        self._validate_operation('create', session_data, ['session_id', 'user_id', 'created_at_ms'])

        # Apply session policy rules
        if self._business_rules:
            rule_result = self._apply_business_rules('session_policy_check', **session_data)
            if not rule_result['valid']:
                return self._mock_operation_result(False, error=f"Session policy violation: {rule_result['violations']}")

        session_id = session_data['session_id']
        self._store[session_id] = session_data.copy()

        return self._mock_operation_result(True, session_id)


@lru_cache(maxsize=10)
def create_contract_mock(store_type: str, client: Mock, tenant_id: Optional[str] = None) -> ContractMockStore:
    """Factory function to create contract-compliant mock stores with caching."""
    mock_classes = {
        'audit': AuditStoreContractMock,
        'user': UserStoreContractMock,
        'device': DeviceStoreContractMock,
        'session': SessionStoreContractMock,
    }

    if store_type not in mock_classes:
        raise ValueError(f"Unknown store type: {store_type}")

    return mock_classes[store_type](client, tenant_id)


def create_optimized_mock_suite(client: Mock, tenant_id: Optional[str] = None) -> Dict[str, ContractMockStore]:
    """Create a suite of optimized contract mocks for all store types."""
    return {
        'audit': create_contract_mock('audit', client, tenant_id),
        'user': create_contract_mock('user', client, tenant_id),
        'device': create_contract_mock('device', client, tenant_id),
        'session': create_contract_mock('session', client, tenant_id),
    }


class MockFirestoreClient:
    """Mock Firestore client that aligns with real Firestore adapter interfaces."""

    def __init__(self, project_id: Optional[str] = None):
        """Initialize mock Firestore client."""
        self.project_id = project_id or 'test-project'
        self._collections: Dict[str, Mock] = {}
        self._enforcer = ContractEnforcer()
        self._validator = ContractValidator()
        self._business_rules = BusinessRules()

    def collection(self, collection_name: str) -> Mock:
        """Get or create a mock collection that behaves like real Firestore."""
        if collection_name not in self._collections:
            # Create a mock collection with Firestore-like behavior
            mock_collection = Mock()
            mock_collection.id = collection_name

            # Mock document reference
            mock_doc = Mock()
            mock_doc.id = None
            mock_doc.collection = mock_collection

            # Mock query behavior
            mock_query = Mock()
            mock_query.where = Mock(return_value=mock_query)
            mock_query.order_by = Mock(return_value=mock_query)
            mock_query.limit = Mock(return_value=mock_query)
            mock_query.offset = Mock(return_value=mock_query)
            mock_query.start_at = Mock(return_value=mock_query)
            mock_query.start_after = Mock(return_value=mock_query)
            mock_query.end_at = Mock(return_value=mock_query)
            mock_query.end_before = Mock(return_value=mock_query)

            # Mock stream that returns empty list by default
            mock_stream = Mock()
            mock_stream.__iter__ = Mock(return_value=iter([]))
            mock_query.stream = Mock(return_value=mock_stream)

            # Set up collection methods
            mock_collection.document = Mock(return_value=mock_doc)
            mock_collection.where = Mock(return_value=mock_query)
            mock_collection.order_by = Mock(return_value=mock_query)
            mock_collection.limit = Mock(return_value=mock_query)
            mock_collection.offset = Mock(return_value=mock_query)
            mock_collection.start_at = Mock(return_value=mock_query)
            mock_collection.start_after = Mock(return_value=mock_query)
            mock_collection.end_at = Mock(return_value=mock_query)
            mock_collection.end_before = Mock(return_value=mock_query)
            mock_collection.stream = Mock(return_value=mock_stream)

            # Add Firestore-specific methods
            mock_collection.add = Mock(return_value=(mock_doc, None))
            mock_collection.get = Mock(return_value=mock_stream)

            self._collections[collection_name] = mock_collection

        return self._collections[collection_name]

    def query(self, collection_name: str, filters: Optional[Dict[str, Any]] = None,
              order_by: Optional[str] = None, limit: Optional[int] = None) -> Mock:
        """
        Perform a query operation that mimics real Firestore behavior.

        Args:
            collection_name: Name of the collection to query
            filters: Query filters to apply
            order_by: Field to order by
            limit: Maximum number of results

        Returns:
            Mock query result with items attribute
        """
        collection = self.collection(collection_name)
        mock_result = Mock()
        mock_result.items = []

        # Apply contract validation if filters are provided
        if filters and self._validator:
            try:
                query_options = QueryOptions(
                    filters=filters,
                    order_by=order_by,
                    limit=limit or 100
                )
                validation = self._validator.validate_query_operation(
                    query_options, collection_name
                )
                if not validation.valid:
                    logger.warning(f"Query validation failed: {validation.violations}")
            except Exception as e:
                logger.warning(f"Query validation error: {e}")

        return mock_result

    def transaction(self) -> Mock:
        """Create a mock transaction context."""
        mock_transaction = Mock()
        mock_transaction.__enter__ = Mock(return_value=mock_transaction)
        mock_transaction.__exit__ = Mock(return_value=None)
        return mock_transaction

    def batch(self) -> Mock:
        """Create a mock batch write context."""
        mock_batch = Mock()
        mock_batch.commit = Mock(return_value=None)
        return mock_batch


def validate_mock_fidelity(mock_client: MockFirestoreClient, real_adapter_methods: List[str]) -> Dict[str, Any]:
    """
    Validate that mock client behavior aligns with real Firestore adapter interfaces.

    Args:
        mock_client: The mock client to validate
        real_adapter_methods: List of methods that real adapters should have

    Returns:
        Dict with validation results
    """
    violations = []
    warnings = []

    # Check that mock client has collection method
    if not hasattr(mock_client, 'collection'):
        violations.append("MockFirestoreClient missing collection() method")
    else:
        # Test collection method returns proper mock
        test_collection = mock_client.collection('test_collection')
        if not hasattr(test_collection, 'document'):
            violations.append("Mock collection missing document() method")
        if not hasattr(test_collection, 'where'):
            violations.append("Mock collection missing where() method")
        if not hasattr(test_collection, 'stream'):
            violations.append("Mock collection missing stream() method")

    # Check that mock client has query method
    if not hasattr(mock_client, 'query'):
        violations.append("MockFirestoreClient missing query() method")
    else:
        # Test query method returns proper result
        test_result = mock_client.query('test_collection', {'tenant_id': 'test'})
        if not hasattr(test_result, 'items'):
            violations.append("Mock query result missing items attribute")

    # Check transaction and batch methods
    if not hasattr(mock_client, 'transaction'):
        warnings.append("MockFirestoreClient missing transaction() method")
    if not hasattr(mock_client, 'batch'):
        warnings.append("MockFirestoreClient missing batch() method")

    # Validate contract integration
    if not hasattr(mock_client, '_validator'):
        violations.append("MockFirestoreClient missing contract validator integration")
    if not hasattr(mock_client, '_enforcer'):
        violations.append("MockFirestoreClient missing contract enforcer integration")

    return {
        'valid': len(violations) == 0,
        'violations': violations,
        'warnings': warnings,
        'checked_methods': ['collection', 'query', 'transaction', 'batch']
    }


# Backward compatibility aliases
ContractAuditStore = AuditStoreContractMock
ContractUserStore = UserStoreContractMock
ContractDeviceStore = DeviceStoreContractMock
ContractSessionStore = SessionStoreContractMock
