"""Runtime contract enforcement plugin for Firestore services.

This plugin provides runtime monitoring and enforcement of contracts for
Firestore service operations, ensuring data integrity and business rule
compliance during actual service execution.
"""

import pytest
import time
import logging
import functools
from typing import Dict, Any, List, Optional, Callable, TypeVar, Union
from contextlib import contextmanager

from ..contracts.firestore import ContractValidator, ContractEnforcer, ContractViolationError
from ..utils.business_rules import BusinessRules

logger = logging.getLogger(__name__)

# Type variables for generic enforcement
T = TypeVar('T')
ServiceMethod = Callable[..., T]


class RuntimeContractEnforcer:
    """Runtime enforcer for Firestore service contracts."""

    def __init__(self, validator: ContractValidator, business_rules: BusinessRules):
        self.validator = validator
        self.business_rules = business_rules
        self.enforcer = ContractEnforcer()
        self.performance_stats = {
            'validations_performed': 0,
            'violations_caught': 0,
            'performance_overhead_ms': 0,
            'services_monitored': set()
        }

    def enforce_create_operation(self, service_name: str, operation: str, data: Dict[str, Any],
                                tenant_id: Optional[str] = None, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Enforce contract for create operations."""
        start_time = time.time()

        try:
            # Pre-validate with business rules
            self._validate_business_rules(operation, data, tenant_id, user_id)

            # Validate against contract
            validation_result = self.validator.validate_create_operation(
                data, operation, tenant_id=tenant_id, user_id=user_id
            )

            if not validation_result.valid:
                raise ContractViolationError(f"Contract violation in {service_name}.{operation}: {validation_result.violations}")

            # Enforce additional runtime checks
            self.enforcer.enforce_create_contract(
                data,
                required_fields=self._get_required_fields(operation),
                tenant_id=tenant_id
            )

            self.performance_stats['validations_performed'] += 1
            self.performance_stats['services_monitored'].add(service_name)

            return data

        except Exception as e:
            self.performance_stats['violations_caught'] += 1
            logger.error(f"Runtime contract enforcement failed for {service_name}.{operation}: {e}")
            raise
        finally:
            overhead = (time.time() - start_time) * 1000
            self.performance_stats['performance_overhead_ms'] += overhead

    def enforce_read_operation(self, service_name: str, operation: str, result: Any,
                              tenant_id: Optional[str] = None, user_id: Optional[str] = None) -> Any:
        """Enforce contract for read operations."""
        start_time = time.time()

        try:
            # Validate read result against contract
            if isinstance(result, dict):
                validation_result = self.validator.validate_read_operation(
                    result, operation, tenant_id=tenant_id
                )

                if not validation_result.valid:
                    logger.warning(f"Read operation contract violation in {service_name}.{operation}: {validation_result.violations}")

            elif isinstance(result, list):
                for item in result:
                    if isinstance(item, dict):
                        validation_result = self.validator.validate_read_operation(
                            item, operation, tenant_id=tenant_id
                        )
                        if not validation_result.valid:
                            logger.warning(f"Read operation contract violation in {service_name}.{operation}: {validation_result.violations}")

            self.performance_stats['validations_performed'] += 1
            return result

        finally:
            overhead = (time.time() - start_time) * 1000
            self.performance_stats['performance_overhead_ms'] += overhead

    def enforce_query_operation(self, service_name: str, operation: str, query_params: Dict[str, Any],
                               tenant_id: Optional[str] = None, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Enforce contract for query operations."""
        start_time = time.time()

        try:
            # Validate query parameters against contract
            from ..contracts.base import QueryOptions
            query_options = QueryOptions(**query_params)

            validation_result = self.validator.validate_query_operation(
                query_options, operation, tenant_id=tenant_id, user_id=user_id
            )

            if not validation_result.valid:
                raise ContractViolationError(f"Query contract violation in {service_name}.{operation}: {validation_result.violations}")

            # Enforce tenant isolation
            if tenant_id and 'filters' in query_params:
                filters = query_params['filters']
                if not any('tenant_id' in str(k) or 'tenant' in str(k).lower() for k in filters.keys()):
                    raise ContractViolationError(f"Tenant isolation violation in {service_name}.{operation}: missing tenant filter")

            self.performance_stats['validations_performed'] += 1
            return query_params

        except Exception as e:
            self.performance_stats['violations_caught'] += 1
            logger.error(f"Runtime query contract enforcement failed for {service_name}.{operation}: {e}")
            raise
        finally:
            overhead = (time.time() - start_time) * 1000
            self.performance_stats['performance_overhead_ms'] += overhead

    def _validate_business_rules(self, operation: str, data: Dict[str, Any],
                                tenant_id: Optional[str] = None, user_id: Optional[str] = None):
        """Validate data against business rules."""
        # Auth validation
        if user_id or tenant_id:
            auth_result = self.business_rules.auth_check(
                user_id=user_id, tenant_id=tenant_id
            )
            if not auth_result['valid']:
                raise ContractViolationError(f"Business rule violation: {auth_result['violations']}")

        # Operation-specific validations
        if operation in ['session', 'user', 'audit_event']:
            # Tenant isolation check
            if tenant_id and 'tenant_id' in data:
                isolation_result = self.business_rules.tenant_isolation_check(
                    tenant_id=tenant_id,
                    resource_tenant_id=data['tenant_id']
                )
                if not isolation_result['valid']:
                    raise ContractViolationError(f"Tenant isolation violation: {isolation_result['violations']}")

        # Session-specific validations
        if operation == 'session' and 'expires_at_ms' in data and 'created_at_ms' in data:
            session_result = self.business_rules.session_policy_check(
                created_at_ms=data['created_at_ms'],
                expires_at_ms=data['expires_at_ms']
            )
            if not session_result['valid']:
                raise ContractViolationError(f"Session policy violation: {session_result['violations']}")

        # Audit trail validation
        audit_result = self.business_rules.audit_trail_check(
            operation=f"create_{operation}",
            user_id=user_id,
            tenant_id=tenant_id
        )
        if not audit_result['valid']:
            raise ContractViolationError(f"Audit trail violation: {audit_result['violations']}")

    def _get_required_fields(self, operation: str) -> List[str]:
        """Get required fields for operation type."""
        required_fields_map = {
            'user': ['user_id', 'username', 'email', 'created_at_ms'],
            'session': ['session_id', 'user_id', 'created_at_ms', 'expires_at_ms'],
            'audit_event': ['event_type', 'timestamp_ms', 'utc_timestamp'],
            'device': ['device_id', 'zone_id', 'created_at_ms'],
            'telemetry': ['device_id', 'sensor_type', 'timestamp_ms']
        }
        return required_fields_map.get(operation, [])

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for contract enforcement."""
        return {
            **self.performance_stats,
            'average_overhead_ms': (
                self.performance_stats['performance_overhead_ms'] / self.performance_stats['validations_performed']
                if self.performance_stats['validations_performed'] > 0 else 0
            ),
            'violation_rate': (
                self.performance_stats['violations_caught'] / self.performance_stats['validations_performed']
                if self.performance_stats['validations_performed'] > 0 else 0
            )
        }


class ServiceWrapper:
    """Wrapper for Firestore services with runtime contract enforcement."""

    def __init__(self, service_instance: Any, service_name: str, enforcer: RuntimeContractEnforcer):
        self._service = service_instance
        self._service_name = service_name
        self._enforcer = enforcer

    def __getattr__(self, name: str) -> Any:
        """Get attribute from wrapped service, wrapping methods with enforcement."""
        attr = getattr(self._service, name)

        if callable(attr):
            return self._wrap_method(attr, name)
        return attr

    def _wrap_method(self, method: ServiceMethod, method_name: str) -> Callable:
        """Wrap a service method with contract enforcement."""

        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            # Extract tenant/user context from kwargs or method signature
            tenant_id = kwargs.get('tenant_id')
            user_id = kwargs.get('user_id')

            # Pre-enforcement for create operations
            if method_name.startswith('create_') or method_name in ['log_event', 'store_sensor_reading', 'register_device']:
                operation = self._infer_operation_type(method_name)
                if args and len(args) > 1:  # First arg is self, second is data
                    data = args[1] if isinstance(args[1], dict) else kwargs
                    if isinstance(data, dict):
                        self._enforcer.enforce_create_operation(
                            self._service_name, operation, data, tenant_id, user_id
                        )

            # Execute the actual method
            result = method(*args, **kwargs)

            # Post-enforcement for read operations
            if method_name.startswith('get_') or method_name.startswith('query_') or method_name == 'log_event':
                operation = self._infer_operation_type(method_name)
                self._enforcer.enforce_read_operation(
                    self._service_name, operation, result, tenant_id, user_id
                )

            return result

        return wrapper

    def _infer_operation_type(self, method_name: str) -> str:
        """Infer the operation type from method name."""
        operation_map = {
            'create_session': 'session',
            'get_session': 'session',
            'query_sessions': 'session',
            'create_user': 'user',
            'get_user': 'user',
            'query_users': 'user',
            'log_event': 'audit_event',
            'query_events': 'audit_event',
            'store_sensor_reading': 'telemetry',
            'get_readings': 'telemetry',
            'register_device': 'device',
            'get_device': 'device',
            'query_devices': 'device'
        }
        return operation_map.get(method_name, 'unknown')


@contextmanager
def runtime_contract_enforcement(service_name: str, enabled: bool = True):
    """Context manager for runtime contract enforcement on a service."""
    if not enabled:
        yield None
        return

    validator = ContractValidator()
    business_rules = BusinessRules()
    enforcer = RuntimeContractEnforcer(validator, business_rules)

    original_init = None

    try:
        # Monkey patch service initialization to wrap instances
        if service_name == 'audit_store':
            from adapters.db.firestore.audit_store import AuditRepository
            original_init = AuditRepository.__init__

            def wrapped_init(self, client):
                original_init(self, client)
                # Wrap the instance
                wrapped_instance = ServiceWrapper(self, service_name, enforcer)
                # Replace self with wrapped instance
                self.__dict__.update(wrapped_instance.__dict__)
                self.__class__ = wrapped_instance.__class__

            AuditRepository.__init__ = wrapped_init

        elif service_name == 'sessions_store':
            from adapters.db.firestore.sessions_store import SessionsStore
            original_init = SessionsStore.__init__

            def wrapped_init(self, client):
                original_init(self, client)
                wrapped_instance = ServiceWrapper(self, service_name, enforcer)
                self.__dict__.update(wrapped_instance.__dict__)
                self.__class__ = wrapped_instance.__class__

            SessionsStore.__init__ = wrapped_init

        yield enforcer

    finally:
        # Restore original initialization
        if original_init:
            if service_name == 'audit_store':
                from adapters.db.firestore.audit_store import AuditRepository
                AuditRepository.__init__ = original_init
            elif service_name == 'sessions_store':
                from adapters.db.firestore.sessions_store import SessionsStore
                SessionsStore.__init__ = original_init


# Pytest plugin hooks
def pytest_configure(config):
    """Configure pytest with runtime contract enforcement."""
    config.addinivalue_line(
        "markers", "runtime_contracts: Enable runtime contract enforcement for these tests"
    )


def pytest_addoption(parser):
    """Add command line options for runtime contract enforcement."""
    group = parser.getgroup("contract")
    group.addoption(
        "--runtime-contract-enforcement",
        action="store_true",
        default=False,
        help="Enable runtime contract enforcement for Firestore services"
    )
    group.addoption(
        "--runtime-contract-services",
        type=str,
        default="audit_store,sessions_store",
        help="Comma-separated list of services to monitor (default: audit_store,sessions_store)"
    )


@pytest.fixture(scope="session")
def runtime_contract_enforcer():
    """Provide runtime contract enforcer instance."""
    validator = ContractValidator()
    business_rules = BusinessRules()
    return RuntimeContractEnforcer(validator, business_rules)


@pytest.fixture(autouse=True)
def enable_runtime_contracts(request, runtime_contract_enforcer):
    """Automatically enable runtime contract enforcement if configured."""
    if not request.config.getoption("--runtime-contract-enforcement"):
        yield
        return

    services_to_monitor = request.config.getoption("--runtime-contract-services").split(',')

    # Set up enforcement for configured services
    enforcers = {}
    for service in services_to_monitor:
        service = service.strip()
        with runtime_contract_enforcement(service, enabled=True) as enforcer:
            enforcers[service] = enforcer

    yield

    # Log performance stats
    for service_name, enforcer in enforcers.items():
        stats = enforcer.get_performance_stats()
        logger.info(f"Runtime contract enforcement stats for {service_name}: {stats}")


@pytest.fixture
def with_runtime_contracts(request):
    """Fixture to enable runtime contracts for specific test."""
    services_to_monitor = getattr(request, 'param', ['audit_store', 'sessions_store'])

    enforcers = {}
    for service in services_to_monitor:
        with runtime_contract_enforcement(service, enabled=True) as enforcer:
            enforcers[service] = enforcer

    yield enforcers

    # Clean up and log stats
    for service_name, enforcer in enforcers.items():
        stats = enforcer.get_performance_stats()
        logger.info(f"Test-specific runtime contract stats for {service_name}: {stats}")
