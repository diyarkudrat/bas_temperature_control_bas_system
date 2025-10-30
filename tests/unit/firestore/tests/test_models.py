"""Tests for Domain Models."""

import pytest
import time
import uuid
from unittest.mock import Mock, patch, MagicMock
import json
import logging
from datetime import datetime
from freezegun import freeze_time

from tests.unit.firestore.mock import (
    MockBaseEntity as BaseEntity, MockTelemetryRecord as TelemetryRecord, MockUser as User, 
    MockSession as Session, MockAuditEvent as AuditEvent, MockDevice as Device,
    create_mock_telemetry_record as create_telemetry_record, create_mock_user as create_user, 
    create_mock_session as create_session, create_mock_audit_event as create_audit_event, 
    create_mock_device as create_device, validate_mock_username as validate_username, 
    validate_mock_role as validate_role
)
# Firestore models under test (server/services/firestore/models.py)
from adapters.db.firestore import models as fs_models
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises

# Contract testing imports
from tests.contracts.firestore import ContractValidator
from tests.utils.business_rules import BusinessRules

# Auth models under test (server/auth/models.py)
from domains.auth.models import User as AuthUser, Session as AuthSession
from domains.auth.serializers import (
    session_from_dict as auth_session_from_dict,
    session_to_dict as auth_session_to_dict,
    user_from_dict as auth_user_from_dict,
    user_to_dict as auth_user_to_dict,
)


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestBaseEntity:
    """Test cases for BaseEntity."""

    @pytest.fixture
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    @pytest.fixture
    def frozen_time(self):
        """Provide frozen time fixture for deterministic timestamp testing."""
        with freeze_time("2022-01-01T12:00:00Z"):
            yield

    def test_base_entity_defaults(self):
        """Test BaseEntity default values."""
        entity = BaseEntity()
        
        assert_is_none(entity.id, "Should have None id")
        assert_is_none(entity.created_at, "Should have None created_at")
        assert_is_none(entity.updated_at, "Should have None updated_at")
    
    def test_base_entity_with_values(self):
        """Test BaseEntity with values."""
        entity = BaseEntity(
            id="test_id",
            created_at=1640995200000,
            updated_at=1640995300000
        )
        
        assert_equals(entity.id, "test_id", "Should set id")
        assert_equals(entity.created_at, 1640995200000, "Should set created_at")
        assert_equals(entity.updated_at, 1640995300000, "Should set updated_at")
    
    def test_base_entity_to_dict(self):
        """Test BaseEntity to_dict method."""
        entity = BaseEntity(
            id="test_id",
            created_at=1640995200000,
            updated_at=1640995300000
        )
        
        result = entity.to_dict()
        
        assert_equals(result['id'], "test_id", "Should include id")
        assert_equals(result['created_at'], 1640995200000, "Should include created_at")
        assert_equals(result['updated_at'], 1640995300000, "Should include updated_at")
    
    def test_base_entity_to_dict_skip_none(self):
        """Test BaseEntity to_dict method skips None values."""
        entity = BaseEntity(id="test_id")  # created_at and updated_at are None
        
        result = entity.to_dict()
        
        assert_equals(result['id'], "test_id", "Should include id")
        assert_true('created_at' not in result, "Should not include None created_at")
        assert_true('updated_at' not in result, "Should not include None updated_at")
    
    def test_base_entity_from_dict(self):
        """Test BaseEntity from_dict method."""
        data = {
            'id': 'test_id',
            'created_at': 1640995200000,
            'updated_at': 1640995300000
        }
        
        entity = BaseEntity.from_dict(data)
        
        assert_equals(entity.id, "test_id", "Should set id")
        assert_equals(entity.created_at, 1640995200000, "Should set created_at")
        assert_equals(entity.updated_at, 1640995300000, "Should set updated_at")
    
    def test_base_entity_from_dict_extra_fields(self):
        """Test BaseEntity from_dict method with extra fields."""
        data = {
            'id': 'test_id',
            'created_at': 1640995200000,
            'extra_field': 'extra_value'  # Should be ignored
        }
        
        entity = BaseEntity.from_dict(data)
        
        assert_equals(entity.id, "test_id", "Should set id")
        assert_equals(entity.created_at, 1640995200000, "Should set created_at")
        assert_false(hasattr(entity, 'extra_field'), "Should not include extra fields")

    # Contract-based validation tests
    def test_contract_validation_base_entity(self, contract_validator, frozen_time):
        """Test contract validation for base entity operations."""
        # Test valid entity data with frozen timestamps
        frozen_timestamp_ms = 1641038400000  # 2022-01-01T12:00:00Z in milliseconds
        entity_data = {
            'id': 'test_id',
            'created_at': frozen_timestamp_ms,
            'updated_at': frozen_timestamp_ms,
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6'
        }

        # Should validate successfully for entity operations
        validation_result = contract_validator.validate_create_operation(
            entity_data,
            'entity',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid, f"Valid entity data should pass validation: {validation_result.violations}")

    def test_business_rules_entity_validation(self, business_rules, frozen_time):
        """Test business rules validation for entities."""
        # Test valid entity operations
        auth_result = business_rules.auth_check(
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            permissions=['read_data']
        )
        assert_true(auth_result['valid'], f"Valid entity auth should pass: {auth_result['violations']}")

        # Test data integrity with frozen timestamp
        frozen_timestamp_ms = 1641038400000  # 2022-01-01T12:00:00Z in milliseconds
        entity_data = {
            'id': 'test_id',
            'created_at': frozen_timestamp_ms
        }

        integrity_result = business_rules.data_integrity_check(entity_data)
        assert_true(integrity_result['valid'], f"Valid data integrity should pass: {integrity_result['violations']}")

    def test_frozen_timestamp_deterministic(self, frozen_time):
        """Test that frozen time provides deterministic timestamps for flakiness detection."""
        import time as time_module

        # Multiple calls to time.time() should return the same frozen value
        timestamp1 = int(time_module.time() * 1000)
        timestamp2 = int(time_module.time() * 1000)

        # Should be exactly the same due to freezing
        assert_equals(timestamp1, timestamp2, "Frozen time should be deterministic")

        # Should match our expected frozen timestamp
        expected_timestamp = 1641038400000  # 2022-01-01T12:00:00Z
        assert_equals(timestamp1, expected_timestamp, "Should match frozen timestamp")


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestTelemetryRecord:
    """Test cases for TelemetryRecord."""
    
    def test_telemetry_record_init_success(self):
        """Test successful TelemetryRecord initialization."""
        record = TelemetryRecord(
            tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
            device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
            timestamp_ms=1640995200000,
            utc_timestamp="2022-01-01T00:00:00Z",
            temp_tenths=230,
            setpoint_tenths=240,
            deadband_tenths=10,
            cool_active=False,
            heat_active=True,
            state="HEATING",
            sensor_ok=True
        )
        
        assert_equals(record.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(record.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")
        assert_equals(record.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(record.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(record.temp_tenths, 230, "Should set temp_tenths")
        assert_equals(record.setpoint_tenths, 240, "Should set setpoint_tenths")
        assert_equals(record.deadband_tenths, 10, "Should set deadband_tenths")
        assert_false(record.cool_active, "Should set cool_active")
        assert_true(record.heat_active, "Should set heat_active")
        assert_equals(record.state, "HEATING", "Should set state")
        assert_true(record.sensor_ok, "Should set sensor_ok")
    
    def test_telemetry_record_init_missing_tenant_id(self):
        """Test TelemetryRecord initialization with missing tenant_id."""
        with assert_raises(ValueError) as exc_info:
            TelemetryRecord(
                tenant_id="",  # Empty tenant_id
                device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
                timestamp_ms=1640995200000,
                utc_timestamp="2022-01-01T00:00:00Z",
                temp_tenths=230,
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=False,
                heat_active=True,
                state="HEATING",
                sensor_ok=True
            )
        
        assert_true('tenant_id' in str(exc_info.value), "Should mention tenant_id requirement")
    
    def test_telemetry_record_init_missing_device_id(self):
        """Test TelemetryRecord initialization with missing device_id."""
        with assert_raises(ValueError) as exc_info:
            TelemetryRecord(
                tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
                device_id="",  # Empty device_id
                timestamp_ms=1640995200000,
                utc_timestamp="2022-01-01T00:00:00Z",
                temp_tenths=230,
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=False,
                heat_active=True,
                state="HEATING",
                sensor_ok=True
            )
        
        assert_true('device_id' in str(exc_info.value), "Should mention device_id requirement")
    
    def test_telemetry_record_init_invalid_timestamp(self):
        """Test TelemetryRecord initialization with invalid timestamp."""
        with assert_raises(ValueError) as exc_info:
            TelemetryRecord(
                tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
                device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
                timestamp_ms=0,  # Invalid timestamp
                utc_timestamp="2022-01-01T00:00:00Z",
                temp_tenths=230,
                setpoint_tenths=240,
                deadband_tenths=10,
                cool_active=False,
                heat_active=True,
                state="HEATING",
                sensor_ok=True
            )
        
        assert_true('timestamp_ms must be positive' in str(exc_info.value), "Should mention timestamp requirement")
    
    def test_telemetry_record_to_dict(self):
        """Test TelemetryRecord to_dict method."""
        record = TelemetryRecord(
            tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
            device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
            timestamp_ms=1640995200000,
            utc_timestamp="2022-01-01T00:00:00Z",
            temp_tenths=230,
            setpoint_tenths=240,
            deadband_tenths=10,
            cool_active=False,
            heat_active=True,
            state="HEATING",
            sensor_ok=True
        )
        
        result = record.to_dict()
        
        assert_equals(result['tenant_id'], "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should include tenant_id")
        assert_equals(result['device_id'], "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should include device_id")
        assert_equals(result['timestamp_ms'], 1640995200000, "Should include timestamp_ms")
        assert_equals(result['temp_tenths'], 230, "Should include temp_tenths")
        assert_false(result['cool_active'], "Should include cool_active")
        assert_true(result['heat_active'], "Should include heat_active")
    
    def test_telemetry_record_from_dict(self):
        """Test TelemetryRecord from_dict method."""
        data = {
            'tenant_id': 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b',
            'device_id': 'h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e',
            'timestamp_ms': 1640995200000,
            'utc_timestamp': '2022-01-01T00:00:00Z',
            'temp_tenths': 230,
            'setpoint_tenths': 240,
            'deadband_tenths': 10,
            'cool_active': False,
            'heat_active': True,
            'state': 'HEATING',
            'sensor_ok': True
        }
        
        record = TelemetryRecord.from_dict(data)
        
        assert_equals(record.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(record.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")
        assert_equals(record.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(record.temp_tenths, 230, "Should set temp_tenths")
        assert_false(record.cool_active, "Should set cool_active")
        assert_true(record.heat_active, "Should set heat_active")
    
    def test_create_telemetry_record(self):
        """Test create_telemetry_record factory function."""
        data = {
            'tenant_id': 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b',
            'device_id': 'h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e',
            'timestamp_ms': 1640995200000,
            'utc_timestamp': '2022-01-01T00:00:00Z',
            'temp_tenths': 230,
            'setpoint_tenths': 240,
            'deadband_tenths': 10,
            'cool_active': False,
            'heat_active': True,
            'state': 'HEATING',
            'sensor_ok': True
        }
        
        record = create_telemetry_record(data)
        
        assert_is_instance(record, TelemetryRecord, "Should return TelemetryRecord instance")
        assert_equals(record.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(record.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")


@pytest.mark.auth
@pytest.mark.unit
class TestUser:
    """Test cases for User."""
    
    def test_user_init_success(self):
        """Test successful User initialization."""
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="operator"
        )
        
        assert_is_not_none(user.user_id, "Should generate user_id")
        assert_equals(user.username, "testuser", "Should set username")
        assert_equals(user.password_hash, "hashed_password_123", "Should set password_hash")
        assert_equals(user.salt, "salt_123", "Should set salt")
        assert_equals(user.role, "operator", "Should set role")
        assert_equals(user.last_login, 0, "Should set default last_login")
        assert_equals(user.failed_attempts, 0, "Should set default failed_attempts")
        assert_equals(user.locked_until, 0, "Should set default locked_until")
        assert_equals(user.password_history, [], "Should set default password_history")
        assert_equals(user.algorithm_params, {}, "Should set default algorithm_params")
    
    def test_user_init_with_custom_user_id(self):
        """Test User initialization with custom user_id."""
        custom_user_id = str(uuid.uuid4())
        
        user = User(
            user_id=custom_user_id,
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123"
        )
        
        assert_equals(user.user_id, custom_user_id, "Should use custom user_id")
    
    def test_user_init_missing_username(self):
        """Test User initialization with missing username."""
        with assert_raises(ValueError) as exc_info:
            User(
                username="",  # Empty username
                password_hash="hashed_password_123",
                salt="salt_123"
            )
        
        assert_true('username is required' in str(exc_info.value), "Should mention username requirement")
    
    def test_user_init_missing_password_hash(self):
        """Test User initialization with missing password_hash."""
        with assert_raises(ValueError) as exc_info:
            User(
                username="testuser",
                password_hash="",  # Empty password_hash
                salt="salt_123"
            )
        
        assert_true('password_hash is required' in str(exc_info.value), "Should mention password_hash requirement")
    
    def test_user_init_missing_salt(self):
        """Test User initialization with missing salt."""
        with assert_raises(ValueError) as exc_info:
            User(
                username="testuser",
                password_hash="hashed_password_123",
                salt=""  # Empty salt
            )
        
        assert_true('salt is required' in str(exc_info.value), "Should mention salt requirement")
    
    def test_user_is_locked_not_locked(self):
        """Test User is_locked property when not locked."""
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            locked_until=0  # Not locked
        )
        
        assert_false(user.is_locked, "Should not be locked")
    
    def test_user_is_locked_future_lock(self):
        """Test User is_locked property when locked in future."""
        future_time = int(time.time() * 1000) + 3600000  # 1 hour from now
        
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            locked_until=future_time
        )
        
        assert_true(user.is_locked, "Should be locked")
    
    def test_user_is_locked_past_lock(self):
        """Test User is_locked property when lock has expired."""
        past_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            locked_until=past_time
        )
        
        assert_false(user.is_locked, "Should not be locked (expired)")
    
    def test_user_is_admin_true(self):
        """Test User is_admin property when user is admin."""
        user = User(
            username="admin",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="admin"
        )
        
        assert_true(user.is_admin, "Should be admin")
    
    def test_user_is_admin_false(self):
        """Test User is_admin property when user is not admin."""
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="operator"
        )
        
        assert_false(user.is_admin, "Should not be admin")
    
    def test_user_is_admin_case_insensitive(self):
        """Test User is_admin property is case insensitive."""
        user = User(
            username="admin",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="ADMIN"  # Uppercase
        )
        
        assert_true(user.is_admin, "Should be admin (case insensitive)")
    
    def test_user_can_access_tenant(self):
        """Test User can_access_tenant method."""
        user = User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123"
        )
        
        # Currently all users can access all tenants
        assert_true(user.can_access_tenant("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"), "Should allow access to any tenant")
        assert_true(user.can_access_tenant("tenant_456"), "Should allow access to any tenant")
    
    def test_user_to_dict(self):
        """Test User to_dict method."""
        user = User(
            user_id="test_user_id",
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="operator",
            last_login=1640995200000,
            failed_attempts=2,
            locked_until=1640995300000,
            password_history=["old_hash1", "old_hash2"],
            algorithm_params={"algorithm": "argon2id"}
        )
        
        result = auth_user_to_dict(user)
        
        assert_equals(result['user_id'], "test_user_id", "Should include user_id")
        assert_equals(result['username'], "testuser", "Should include username")
        assert_equals(result['password_hash'], "hashed_password_123", "Should include password_hash")
        assert_equals(result['role'], "operator", "Should include role")
        assert_equals(result['last_login'], 1640995200000, "Should include last_login")
        assert_equals(result['failed_attempts'], 2, "Should include failed_attempts")
        assert_equals(result['locked_until'], 1640995300000, "Should include locked_until")
        assert_equals(result['password_history'], ["old_hash1", "old_hash2"], "Should include password_history")
        assert_equals(result['algorithm_params'], {"algorithm": "argon2id"}, "Should include algorithm_params")
    
    def test_user_from_dict(self):
        """Test User from_dict method."""
        data = {
            'user_id': 'test_user_id',
            'username': 'testuser',
            'password_hash': 'hashed_password_123',
            'salt': 'salt_123',
            'role': 'operator',
            'last_login': 1640995200000,
            'failed_attempts': 2,
            'locked_until': 1640995300000,
            'password_history': ['old_hash1', 'old_hash2'],
            'algorithm_params': {'algorithm': 'argon2id'}
        }
        
        user = User.from_dict(data)
        
        assert_equals(user.user_id, "test_user_id", "Should set user_id")
        assert_equals(user.username, "testuser", "Should set username")
        assert_equals(user.password_hash, "hashed_password_123", "Should set password_hash")
        assert_equals(user.salt, "salt_123", "Should set salt")
        assert_equals(user.role, "operator", "Should set role")
        assert_equals(user.last_login, 1640995200000, "Should set last_login")
        assert_equals(user.failed_attempts, 2, "Should set failed_attempts")
        assert_equals(user.locked_until, 1640995300000, "Should set locked_until")
        assert_equals(user.password_history, ["old_hash1", "old_hash2"], "Should set password_history")
        assert_equals(user.algorithm_params, {"algorithm": "argon2id"}, "Should set algorithm_params")
    
    def test_create_user(self):
        """Test create_user factory function."""
        data = {
            'user_id': 'test_user_id',
            'username': 'testuser',
            'password_hash': 'hashed_password_123',
            'salt': 'salt_123',
            'role': 'operator'
        }
        
        user = create_user(data)
        
        assert_is_instance(user, User, "Should return User instance")
        assert_equals(user.user_id, "test_user_id", "Should set user_id")
        assert_equals(user.username, "testuser", "Should set username")


@pytest.mark.auth
@pytest.mark.unit
class TestSession:
    """Test cases for Session."""
    
    def test_session_init_success(self):
        """Test successful Session initialization."""
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            role="operator",
            created_at=1640995200000,
            expires_at=1640998800000,
            last_access=1640995200000,
            fingerprint="fp_abc123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            tenant_id="tenant_789"
        )
        
        assert_equals(session.session_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479", "Should set session_id")
        assert_equals(session.user_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should set user_id")
        assert_equals(session.username, "testuser", "Should set username")
        assert_equals(session.role, "operator", "Should set role")
        assert_equals(session.created_at, 1640995200000, "Should set created_at")
        assert_equals(session.expires_at, 1640998800000, "Should set expires_at")
        assert_equals(session.last_access, 1640995200000, "Should set last_access")
        assert_equals(session.fingerprint, "fp_abc123", "Should set fingerprint")
        assert_equals(session.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(session.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(session.tenant_id, "tenant_789", "Should set tenant_id")
    
    def test_session_init_missing_session_id(self):
        """Test Session initialization with missing session_id."""
        with assert_raises(ValueError) as exc_info:
            Session(
                session_id="",  # Empty session_id
                user_id="user_456",
                username="testuser"
            )
        
        assert_true('session_id is required' in str(exc_info.value), "Should mention session_id requirement")
    
    def test_session_init_missing_user_id(self):
        """Test Session initialization with missing user_id."""
        with assert_raises(ValueError) as exc_info:
            Session(
                session_id="sess_123",
                user_id="",  # Empty user_id
                username="testuser"
            )
        
        assert_true('user_id is required' in str(exc_info.value), "Should mention user_id requirement")
    
    def test_session_init_missing_username(self):
        """Test Session initialization with missing username."""
        with assert_raises(ValueError) as exc_info:
            Session(
                session_id="sess_123",
                user_id="user_456",
                username=""  # Empty username
            )
        
        assert_true('username is required' in str(exc_info.value), "Should mention username requirement")
    
    def test_session_is_expired_not_expired(self):
        """Test Session is_expired property when not expired."""
        future_time = int(time.time() * 1000) + 3600000  # 1 hour from now
        
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            expires_at=future_time
        )
        
        assert_false(session.is_expired, "Should not be expired")
    
    def test_session_is_expired_expired(self):
        """Test Session is_expired property when expired."""
        past_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            expires_at=past_time
        )
        
        assert_true(session.is_expired, "Should be expired")
    
    def test_session_is_valid_valid(self):
        """Test Session is_valid property when valid."""
        future_time = int(time.time() * 1000) + 3600000  # 1 hour from now
        
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            expires_at=future_time
        )
        
        assert_true(session.is_valid, "Should be valid")
    
    def test_session_is_valid_invalid(self):
        """Test Session is_valid property when invalid."""
        past_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            expires_at=past_time
        )
        
        assert_false(session.is_valid, "Should not be valid")
    
    def test_session_extend_session(self):
        """Test Session extend_session method."""
        original_expires_at = 1640995200000
        
        session = Session(
            session_id="sess_123",
            user_id="user_456",
            username="testuser",
            expires_at=original_expires_at
        )
        
        session.extend_session(1800)  # Extend by 30 minutes (1800 seconds)
        
        expected_expires_at = original_expires_at + (1800 * 1000)  # Convert to milliseconds
        assert_equals(session.expires_at, expected_expires_at, "Should extend expiration time")
    
    def test_session_to_dict(self):
        """Test Session to_dict method."""
        session = Session(
            session_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            role="operator",
            created_at=1640995200000,
            expires_at=1640998800000,
            last_access=1640995200000,
            fingerprint="fp_abc123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            tenant_id="tenant_789"
        )
        
        result = auth_session_to_dict(session)
        
        assert_equals(result['session_id'], "f47ac10b-58cc-4372-a567-0e02b2c3d479", "Should include session_id")
        assert_equals(result['user_id'], "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should include user_id")
        assert_equals(result['username'], "testuser", "Should include username")
        assert_equals(result['role'], "operator", "Should include role")
        assert_equals(result['created_at'], 1640995200000, "Should include created_at")
        assert_equals(result['expires_at'], 1640998800000, "Should include expires_at")
        assert_equals(result['fingerprint'], "fp_abc123", "Should include fingerprint")
        assert_equals(result['ip_address'], "192.168.1.100", "Should include ip_address")
        assert_equals(result['user_agent'], "Mozilla/5.0", "Should include user_agent")
        assert_equals(result['tenant_id'], "tenant_789", "Should include tenant_id")
    
    def test_session_from_dict(self):
        """Test Session from_dict method."""
        data = {
            'session_id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'username': 'testuser',
            'role': 'operator',
            'created_at': 1640995200000,
            'expires_at': 1640998800000,
            'last_access': 1640995200000,
            'fingerprint': 'fp_abc123',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0',
            'tenant_id': 'tenant_789'
        }
        
        session = Session.from_dict(data)
        
        assert_equals(session.session_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479", "Should set session_id")
        assert_equals(session.user_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should set user_id")
        assert_equals(session.username, "testuser", "Should set username")
        assert_equals(session.role, "operator", "Should set role")
        assert_equals(session.created_at, 1640995200000, "Should set created_at")
        assert_equals(session.expires_at, 1640998800000, "Should set expires_at")
        assert_equals(session.last_access, 1640995200000, "Should set last_access")
        assert_equals(session.fingerprint, "fp_abc123", "Should set fingerprint")
        assert_equals(session.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(session.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(session.tenant_id, "tenant_789", "Should set tenant_id")
    
    def test_create_session(self):
        """Test create_session factory function."""
        data = {
            'session_id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'username': 'testuser',
            'role': 'operator'
        }
        
        session = create_session(data)
        
        assert_is_instance(session, Session, "Should return Session instance")
        assert_equals(session.session_id, "f47ac10b-58cc-4372-a567-0e02b2c3d479", "Should set session_id")
        assert_equals(session.user_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should set user_id")


@pytest.mark.auth
@pytest.mark.unit
class TestAuditEvent:
    """Test cases for AuditEvent."""
    
    def test_audit_event_init_success(self):
        """Test successful AuditEvent initialization."""
        event = AuditEvent(
            timestamp_ms=1640995200000,
            utc_timestamp="2022-01-01T00:00:00Z",
            event_type="LOGIN_SUCCESS",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            details={"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
            tenant_id="tenant_789"
        )
        
        assert_equals(event.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(event.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(event.event_type, "LOGIN_SUCCESS", "Should set event_type")
        assert_equals(event.user_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should set user_id")
        assert_equals(event.username, "testuser", "Should set username")
        assert_equals(event.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(event.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(event.details, {"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, "Should set details")
        assert_equals(event.tenant_id, "tenant_789", "Should set tenant_id")
    
    def test_audit_event_init_minimal(self):
        """Test AuditEvent initialization with minimal data."""
        event = AuditEvent(
            timestamp_ms=1640995200000,
            utc_timestamp="2022-01-01T00:00:00Z",
            event_type="SYSTEM_STARTUP"
        )
        
        assert_equals(event.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(event.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(event.event_type, "SYSTEM_STARTUP", "Should set event_type")
        assert_is_none(event.user_id, "Should have None user_id")
        assert_is_none(event.username, "Should have None username")
        assert_is_none(event.ip_address, "Should have None ip_address")
        assert_is_none(event.user_agent, "Should have None user_agent")
        assert_equals(event.details, {}, "Should have empty details dict")
        assert_is_none(event.tenant_id, "Should have None tenant_id")
    
    def test_audit_event_init_missing_event_type(self):
        """Test AuditEvent initialization with missing event_type."""
        with assert_raises(ValueError) as exc_info:
            AuditEvent(
                timestamp_ms=1640995200000,
                utc_timestamp="2022-01-01T00:00:00Z",
                event_type=""  # Empty event_type
            )
        
        assert_true('event_type is required' in str(exc_info.value), "Should mention event_type requirement")
    
    def test_audit_event_to_dict(self):
        """Test AuditEvent to_dict method."""
        event = AuditEvent(
            timestamp_ms=1640995200000,
            utc_timestamp="2022-01-01T00:00:00Z",
            event_type="LOGIN_SUCCESS",
            user_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            username="testuser",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            details={"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
            tenant_id="tenant_789"
        )
        
        result = event.to_dict()
        
        assert_equals(result['timestamp_ms'], 1640995200000, "Should include timestamp_ms")
        assert_equals(result['utc_timestamp'], "2022-01-01T00:00:00Z", "Should include utc_timestamp")
        assert_equals(result['event_type'], "LOGIN_SUCCESS", "Should include event_type")
        assert_equals(result['user_id'], "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should include user_id")
        assert_equals(result['username'], "testuser", "Should include username")
        assert_equals(result['ip_address'], "192.168.1.100", "Should include ip_address")
        assert_equals(result['user_agent'], "Mozilla/5.0", "Should include user_agent")
        assert_equals(result['details'], {"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, "Should include details")
        assert_equals(result['tenant_id'], "tenant_789", "Should include tenant_id")
    
    def test_audit_event_from_dict(self):
        """Test AuditEvent from_dict method."""
        data = {
            'timestamp_ms': 1640995200000,
            'utc_timestamp': '2022-01-01T00:00:00Z',
            'event_type': 'LOGIN_SUCCESS',
            'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'username': 'testuser',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0',
            'details': {'session_id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479'},
            'tenant_id': 'tenant_789'
        }
        
        event = AuditEvent.from_dict(data)
        
        assert_equals(event.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(event.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(event.event_type, "LOGIN_SUCCESS", "Should set event_type")
        assert_equals(event.user_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "Should set user_id")
        assert_equals(event.username, "testuser", "Should set username")
        assert_equals(event.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(event.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(event.details, {"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, "Should set details")
        assert_equals(event.tenant_id, "tenant_789", "Should set tenant_id")
    
    def test_create_audit_event(self):
        """Test create_audit_event factory function."""
        data = {
            'timestamp_ms': 1640995200000,
            'utc_timestamp': '2022-01-01T00:00:00Z',
            'event_type': 'LOGIN_SUCCESS',
            'username': 'testuser'
        }
        
        event = create_audit_event(data)
        
        assert_is_instance(event, AuditEvent, "Should return AuditEvent instance")
        assert_equals(event.event_type, "LOGIN_SUCCESS", "Should set event_type")
        assert_equals(event.username, "testuser", "Should set username")


@pytest.mark.auth
@pytest.mark.unit
class TestDevice:
    """Test cases for Device."""
    
    def test_device_init_success(self):
        """Test successful Device initialization."""
        device = Device(
            tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
            device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
            metadata={"location": "Building A", "model": "Thermostat V2"},
            status="active"
        )
        
        assert_equals(device.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(device.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")
        assert_equals(device.metadata, {"location": "Building A", "model": "Thermostat V2"}, "Should set metadata")
        assert_equals(device.status, "active", "Should set status")
    
    def test_device_init_defaults(self):
        """Test Device initialization with defaults."""
        device = Device(
            tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
            device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e"
        )
        
        assert_equals(device.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(device.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")
        assert_equals(device.metadata, {}, "Should set default empty metadata")
        assert_equals(device.status, "active", "Should set default status")
    
    def test_device_to_dict(self):
        """Test Device to_dict method."""
        device = Device(
            tenant_id="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b",
            device_id="h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e",
            metadata={"location": "Building A", "model": "Thermostat V2"},
            status="active"
        )
        
        result = device.to_dict()
        
        assert_equals(result['tenant_id'], "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should include tenant_id")
        assert_equals(result['device_id'], "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should include device_id")
        assert_equals(result['metadata'], {"location": "Building A", "model": "Thermostat V2"}, "Should include metadata")
        assert_equals(result['status'], "active", "Should include status")
    
    def test_device_from_dict(self):
        """Test Device from_dict method."""
        data = {
            'tenant_id': 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b',
            'device_id': 'h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e',
            'metadata': {'location': 'Building A', 'model': 'Thermostat V2'},
            'status': 'active'
        }
        
        device = Device.from_dict(data)
        
        assert_equals(device.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(device.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")
        assert_equals(device.metadata, {"location": "Building A", "model": "Thermostat V2"}, "Should set metadata")
        assert_equals(device.status, "active", "Should set status")
    
    def test_create_device(self):
        """Test create_device factory function."""
        data = {
            'tenant_id': 'e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b',
            'device_id': 'h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e',
            'metadata': {'location': 'Building A'},
            'status': 'active'
        }
        
        device = create_device(data)
        
        assert_is_instance(device, Device, "Should return Device instance")
        assert_equals(device.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id")
        assert_equals(device.device_id, "h8c9d0e1-f2a3-4b5c-9d0e-1f2a3b4c5d6e", "Should set device_id")


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestValidationFunctions:
    """Test cases for validation functions."""

    @pytest.fixture
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    def test_validate_username_valid(self):
        """Test validate_username with valid usernames."""
        valid_usernames = [
            "testuser",
            "user123",
            "admin_user",
            "test-user",
            "user.name",
            "a",  # Minimum length
            "a" * 50  # Maximum reasonable length
        ]
        
        for username in valid_usernames:
            assert_true(validate_username(username), f"Should validate {username} as valid")
    
    def test_validate_username_invalid(self):
        """Test validate_username with invalid usernames."""
        invalid_usernames = [
            "",  # Empty
            " ",  # Whitespace only
            "user@domain",  # Contains @
            "user with spaces",  # Contains spaces
            "user\nwith\nnewlines",  # Contains newlines
            "user\twith\ttabs",  # Contains tabs
            "user<script>",  # Contains HTML
            "user'with'quotes",  # Contains quotes
            "user\"with\"doublequotes",  # Contains double quotes
            "user;with;semicolon",  # Contains semicolon
            "user(with)parentheses",  # Contains parentheses
            "user{with}braces",  # Contains braces
            "user[with]brackets",  # Contains brackets
            "user|with|pipe",  # Contains pipe
            "user\\with\\backslash",  # Contains backslash
            "user/with/forward"  # Contains forward slash
        ]
        
        for username in invalid_usernames:
            assert_false(validate_username(username), f"Should reject {repr(username)} as invalid")
    
    def test_validate_role_valid(self):
        """Test validate_role with valid roles."""
        valid_roles = [
            "admin",
            "operator",
            "viewer",
            "guest",
            "super_admin",
            "system_admin",
            "read_only"
        ]
        
        for role in valid_roles:
            assert_true(validate_role(role), f"Should validate {role} as valid")
    
    def test_validate_role_invalid(self):
        """Test validate_role with invalid roles."""
        invalid_roles = [
            "",  # Empty
            " ",  # Whitespace only
            "admin role",  # Contains spaces
            "admin@role",  # Contains special characters
            "admin;role",  # Contains semicolon
            "admin'role",  # Contains quotes
            "admin\"role",  # Contains double quotes
            "admin(role)",  # Contains parentheses
            "admin[role]",  # Contains brackets
            "admin{role}",  # Contains braces
            "admin|role",  # Contains pipe
            "admin\\role",  # Contains backslash
            "admin/role",  # Contains forward slash
            "admin\nrole",  # Contains newlines
            "admin\trole"  # Contains tabs
        ]
        
        for role in invalid_roles:
            assert_false(validate_role(role), f"Should reject {repr(role)} as invalid")
    
    def test_validate_username_edge_cases(self):
        """Test validate_username with edge cases."""
        # Test with very long username
        long_username = "a" * 1000
        assert_false(validate_username(long_username), "Should reject very long username")
        
        # Test with unicode characters (should be valid)
        unicode_username = "user_测试"
        assert_true(validate_username(unicode_username), "Should accept unicode characters")
        
        # Test with numbers and underscores
        numeric_username = "user_123_456"
        assert_true(validate_username(numeric_username), "Should accept numbers and underscores")
    
    def test_validate_role_edge_cases(self):
        """Test validate_role with edge cases."""
        # Test with very long role
        long_role = "a" * 1000
        assert_false(validate_role(long_role), "Should reject very long role")
        
        # Test with unicode characters (should be valid)
        unicode_role = "admin_测试"
        assert_true(validate_role(unicode_role), "Should accept unicode characters")
        
        # Test with numbers and underscores
        numeric_role = "admin_123_456"
        assert_true(validate_role(numeric_role), "Should accept numbers and underscores")

    # Contract-based validation tests
    def test_contract_validation_model_creation(self, contract_validator):
        """Test contract validation for model creation operations."""
        # Test valid user model data
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password_hash': 'hashed_password',
            'role': 'admin',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'created_at_ms': int(time.time() * 1000)
        }

        validation_result = contract_validator.validate_create_operation(
            user_data,
            'user',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(validation_result.valid, f"Valid user model should pass validation: {validation_result.violations}")

        # Test valid device model data
        device_data = {
            'device_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'status': 'active',
            'metadata': {'location': 'test'},
            'created_at_ms': int(time.time() * 1000)
        }

        device_result = contract_validator.validate_create_operation(
            device_data,
            'device',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(device_result.valid, f"Valid device model should pass validation: {device_result.violations}")

    def test_contract_violation_invalid_model_data(self, contract_validator):
        """Test contract violation for invalid model data."""
        # Test invalid user data
        invalid_user_data = {
            'username': '',  # Invalid empty username
            'email': 'invalid-email',
            'password_hash': 'short',
            'role': 'invalid_role',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6'
        }

        user_result = contract_validator.validate_create_operation(
            invalid_user_data,
            'user',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_false(user_result.valid, "Invalid user model should fail validation")
        assert_true(len(user_result.violations) > 0, "Should have validation violations")

        # Test invalid device data
        invalid_device_data = {
            'device_id': 'device-123',
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'status': 'invalid_status',  # Invalid status
            'metadata': {'location': 'test'}
        }

        device_result = contract_validator.validate_create_operation(
            invalid_device_data,
            'device',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_false(device_result.valid, "Invalid device model should fail validation")
        assert_true(len(device_result.violations) > 0, "Should have validation violations")

    def test_business_rules_model_validation(self, business_rules):
        """Test business rules validation for models."""
        # Test username validation through business rules
        # Note: The business rules don't directly validate usernames,
        # but they validate user_id format which is similar
        auth_result = business_rules.auth_check(
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            permissions=['create_user']
        )
        assert_true(auth_result['valid'], f"Valid user auth should pass: {auth_result['violations']}")

        # Test tenant isolation for models
        isolation_result = business_rules.tenant_isolation_check(
            '3fa85f64-5717-4562-b3fc-2c963f66afa6', '3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        assert_true(isolation_result['valid'], f"Valid tenant isolation should pass: {isolation_result['violations']}")

        # Test invalid tenant isolation
        invalid_isolation = business_rules.tenant_isolation_check(
            '3fa85f64-5717-4562-b3fc-2c963f66afa6', 'y3z4a5b6-c7d8-4e9f-0a1b-2c3d4e5f6g7h'
        )
        assert_false(invalid_isolation['valid'], "Invalid tenant isolation should fail")
        assert_true(len(invalid_isolation['violations']) > 0, "Should have isolation violations")

    def test_contract_validator_model_integration(self, contract_validator, business_rules):
        """Test contract validator integration with model validation."""
        # Test that contract validator properly validates model data
        # using the business rules internally

        # Test password policy validation
        password_result = contract_validator.validate_business_rules(
            'password_policy',
            {'password': 'ValidPass123!'}
        )
        assert_true(password_result['valid'], f"Valid password should pass: {password_result['violations']}")

        # Test invalid password
        invalid_password_result = contract_validator.validate_business_rules(
            'password_policy',
            {'password': 'weak'}
        )
        assert_false(invalid_password_result['valid'], "Invalid password should fail")
        assert_true(len(invalid_password_result['violations']) > 0, "Should have password violations")

# ---------------------------------------------------------------------------
# Auth Models (server/auth/models.py) branch coverage
# ---------------------------------------------------------------------------

@pytest.mark.auth
@pytest.mark.unit
class TestAuthUserModels:
    """Branch coverage for AuthUser in server/auth/models.py"""

    def test_user_is_locked_false(self):
        user = AuthUser(username="u", password_hash="p", salt="s", locked_until=0)
        assert_false(user.is_locked(), "User should not be locked when locked_until <= now")

    def test_user_is_locked_true_and_logs(self, caplog):
        future = time.time() + 3600
        user = AuthUser(username="u", password_hash="p", salt="s", locked_until=future)
        with caplog.at_level(logging.WARNING):
            result = user.is_locked()
        assert_true(result, "User should be locked when locked_until > now")
        assert_true(any("is locked until" in r.message for r in caplog.records), "Should log a warning when locked")

    def test_user_to_dict_password_history_json(self):
        user = AuthUser(username="u", password_hash="p", salt="s", password_history=["a", "b"])
        result = auth_user_to_dict(user)
        assert_true(isinstance(result["password_history"], str), "password_history should be JSON string")
        parsed = json.loads(result["password_history"])
        assert_equals(parsed, ["a", "b"], "password_history JSON should round-trip to list")

    def test_user_from_dict_valid_values(self):
        data = {
            "username": "u",
            "password_hash": "p",
            "salt": "s",
            "role": "admin",
            "created_at": 1000.0,
            "last_login": 10.0,
            "failed_attempts": 1,
            "locked_until": 2.0,
            "password_history": json.dumps(["old1", "old2"]),
        }
        user = auth_user_from_dict(data)
        assert_equals(user.username, "u", "Should set username")
        assert_equals(user.password_hash, "p", "Should set password_hash")
        assert_equals(user.salt, "s", "Should set salt")
        assert_equals(user.role, "admin", "Role should be preserved when valid")
        assert_equals(user.created_at, 1000.0, "created_at should be preserved when valid")
        assert_equals(user.last_login, 10.0, "last_login should be preserved when valid")
        assert_equals(user.failed_attempts, 1, "failed_attempts should be preserved when valid")
        assert_equals(user.locked_until, 2.0, "locked_until should be preserved when valid")
        assert_equals(user.password_history, ["old1", "old2"], "password_history should parse from JSON list")

    def test_user_from_dict_password_history_invalid_json(self):
        data = {"username": "u", "password_hash": "p", "salt": "s", "password_history": "not-json"}
        user = auth_user_from_dict(data)
        assert_equals(user.password_history, [], "Invalid JSON should yield empty password_history list")

    def test_user_from_dict_password_history_non_list_json(self):
        data = {"username": "u", "password_hash": "p", "salt": "s", "password_history": json.dumps("hello")}
        user = auth_user_from_dict(data)
        assert_equals(user.password_history, [], "Non-list JSON should yield empty password_history list")

    def test_user_from_dict_password_history_none(self):
        data = {"username": "u", "password_hash": "p", "salt": "s", "password_history": None}
        user = auth_user_from_dict(data)
        assert_equals(user.password_history, [], "None password_history should yield empty list")

    def test_user_from_dict_numeric_and_role_validation_with_freeze(self):
        with freeze_time("2022-01-01T12:00:00Z"):
            now_ts = time.time()
            data = {
                "username": "u",
                "password_hash": "p",
                "salt": "s",
                "created_at": "bad",   # invalid -> now
                "last_login": -5,        # negative -> 0
                "failed_attempts": -1,   # negative -> 0
                "locked_until": "bad",  # invalid -> 0
                "role": "INVALID_ROLE", # invalid -> operator
            }
            user = auth_user_from_dict(data)
            assert_equals(user.created_at, now_ts, "Invalid created_at should default to now")
            assert_equals(user.last_login, 0, "Negative last_login should default to 0")
            assert_equals(user.failed_attempts, 0, "Negative failed_attempts should default to 0")
            assert_equals(user.locked_until, 0, "Invalid locked_until should default to 0")
            assert_equals(user.role, "operator", "Invalid role should default to operator")

    def test_user_from_dict_role_allowed_read_only(self):
        data = {"username": "u", "password_hash": "p", "salt": "s", "role": "read-only"}
        user = auth_user_from_dict(data)
        assert_equals(user.role, "read-only", "Allowed role read-only should be preserved")

    def test_user_from_dict_missing_required_keys(self):
        with assert_raises(KeyError):
            auth_user_from_dict({"password_hash": "p", "salt": "s"})  # missing username


@pytest.mark.auth
@pytest.mark.unit
class TestAuthSessionModels:
    """Branch coverage for AuthSession in server/auth/models.py"""

    def _make_session(self, **overrides):
        base = dict(
            session_id="sess-1",
            username="u",
            role="operator",
            created_at=time.time(),
            expires_at=time.time() + 3600,
            last_access=time.time(),
            fingerprint="fp",
            ip_address="127.0.0.1",
            user_agent="UA",
            user_id="uid-1",
            tenant_id="ten-1",
        )
        base.update(overrides)
        return AuthSession(**base)

    def test_session_is_expired_false(self):
        with freeze_time("2022-01-01T12:00:00Z"):
            now_ts = time.time()
            sess = self._make_session(created_at=now_ts, expires_at=now_ts + 60)
            assert_false(sess.is_expired(), "Session should not be expired when expires_at > now")

    def test_session_is_expired_true_and_logs(self, caplog):
        with freeze_time("2022-01-01T12:00:00Z"):
            now_ts = time.time()
            sess = self._make_session(created_at=now_ts, expires_at=now_ts - 1)
            with caplog.at_level(logging.DEBUG):
                result = sess.is_expired()
            assert_true(result, "Session should be expired when expires_at < now")
            assert_true(any("has expired" in r.message for r in caplog.records), "Should log debug when expired")

    def test_session_to_dict_fields(self):
        sess = self._make_session()
        d = sess.to_dict()
        for key in [
            "session_id", "username", "role", "created_at", "expires_at",
            "last_access", "fingerprint", "ip_address", "user_agent",
            "user_id", "tenant_id",
        ]:
            assert_true(key in d, f"to_dict should include {key}")

    def test_session_from_dict_valid_and_role_preserved(self):
        data = {
            "session_id": "s1",
            "username": "u",
            "role": "admin",
            "created_at": 1000.0,
            "expires_at": 2000.0,
            "last_access": 1500.0,
            "fingerprint": "fp",
            "ip_address": "127.0.0.1",
            "user_agent": "UA",
            "user_id": "uid-1",
            "tenant_id": "ten-1",
        }
        sess = auth_session_from_dict(data)
        assert_equals(sess.role, "admin", "Valid role should be preserved")
        assert_equals(sess.created_at, 1000.0, "created_at should be preserved")
        assert_equals(sess.expires_at, 2000.0, "expires_at should be preserved")
        assert_equals(sess.last_access, 1500.0, "last_access should be preserved")

    def test_session_from_dict_role_invalid_defaults(self):
        data = {
            "session_id": "s1",
            "username": "u",
            "role": "SUPER",
            "created_at": 1000.0,
            "expires_at": 2000.0,
            "last_access": 1500.0,
            "fingerprint": "fp",
            "ip_address": "127.0.0.1",
            "user_agent": "UA",
        }
        sess = auth_session_from_dict(data)
        assert_equals(sess.role, "operator", "Invalid role should default to operator")
        assert_equals(sess.user_id, "unknown", "Missing user_id should default to 'unknown'")
        assert_is_none(sess.tenant_id, "Missing tenant_id should default to None")

    def test_session_from_dict_invalid_numeric_and_order_with_freeze(self):
        with freeze_time("2022-01-01T12:00:00Z"):
            now_ts = time.time()
            data = {
                "session_id": "s1",
                "username": "u",
                "role": "operator",
                "created_at": "bad",       # -> now
                "expires_at": -1,            # invalid -> created_at + 1800
                "last_access": -5,           # invalid -> created_at
                "fingerprint": "fp",
                "ip_address": "127.0.0.1",
                "user_agent": "UA",
            }
            sess = auth_session_from_dict(data)
            assert_equals(sess.created_at, now_ts, "Invalid created_at should default to now")
            assert_equals(sess.expires_at, now_ts + 1800, "Invalid expires_at should default to created_at + 1800")
            assert_equals(sess.last_access, now_ts, "Invalid last_access should default to created_at")

    def test_session_from_dict_last_access_before_created_at(self):
        data = {
            "session_id": "s1",
            "username": "u",
            "role": "operator",
            "created_at": 2000.0,
            "expires_at": 4000.0,
            "last_access": 1000.0,  # < created_at -> clamp
            "fingerprint": "fp",
            "ip_address": "127.0.0.1",
            "user_agent": "UA",
        }
        sess = auth_session_from_dict(data)
        assert_equals(sess.last_access, 2000.0, "last_access earlier than created_at should clamp to created_at")

    def test_session_from_dict_missing_required_keys(self):
        with assert_raises(KeyError):
            auth_session_from_dict({"username": "u"})  # missing many required keys


# ---------------------------------------------------------------------------
# Firestore Models (server/services/firestore/models.py) branch coverage
# ---------------------------------------------------------------------------

@pytest.mark.firestore
@pytest.mark.unit
class TestFsBaseEntity:
    def test_fs_base_entity_to_dict_skips_none(self):
        e = fs_models.BaseEntity(id="x", created_at=None, updated_at=None)
        d = e.to_dict()
        assert_true("id" in d and d["id"] == "x", "Should include non-None fields")
        assert_true("created_at" not in d and "updated_at" not in d, "Should skip None fields")

    def test_fs_base_entity_from_dict_ignores_extra(self):
        e = fs_models.BaseEntity.from_dict({"id": "x", "created_at": 1, "zzz": 2})
        assert_equals(e.id, "x", "Should set known fields")
        assert_equals(e.created_at, 1, "Should set known fields")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsAuditEvent:
    def test_fs_audit_event_invalid_timestamp_raises(self):
        with assert_raises(ValueError) as exc:
            fs_models.AuditEvent(timestamp_ms=0, utc_timestamp="2022-01-01T00:00:00Z", event_type="X")
        assert_true("timestamp_ms must be positive" in str(exc.value), "Should validate positive timestamp")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsDevice:
    def test_fs_device_missing_tenant_or_device_raises(self):
        with assert_raises(ValueError):
            fs_models.Device(tenant_id="", device_id="d1")
        with assert_raises(ValueError):
            fs_models.Device(tenant_id="t1", device_id="")

    def test_fs_device_is_online_paths(self):
        with freeze_time("2022-01-01T12:00:00Z"):
            now_ms = int(time.time() * 1000)
            d = fs_models.Device(tenant_id="t1", device_id="d1")
            # last_seen == 0 -> False
            assert_false(d.is_online, "Zero last_seen should be offline")
            # within the last hour -> True
            d.last_seen = now_ms - (30 * 60 * 1000)
            assert_true(d.is_online, "Seen within last hour should be online")
            # older than one hour -> False
            d.last_seen = now_ms - (61 * 60 * 1000)
            assert_false(d.is_online, "Seen >1h ago should be offline")

    def test_fs_device_is_active_property(self):
        d1 = fs_models.Device(tenant_id="t1", device_id="d1", status="active")
        d2 = fs_models.Device(tenant_id="t1", device_id="d2", status="INACTIVE")
        assert_true(d1.is_active, "active should be True")
        assert_false(d2.is_active, "non-active should be False")

    def test_fs_device_update_last_seen_sets_now(self):
        with freeze_time("2022-01-01T12:00:00Z"):
            expected_ms = int(time.time() * 1000)
            d = fs_models.Device(tenant_id="t1", device_id="d1")
            d.update_last_seen()
            assert_equals(d.last_seen, expected_ms, "update_last_seen should set current ms timestamp")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsFactoryFunctions:
    def test_fs_create_functions(self):
        # TelemetryRecord
        tr = fs_models.create_telemetry_record({
            "tenant_id": "t1", "device_id": "d1", "timestamp_ms": 1,
            "utc_timestamp": "2022-01-01T00:00:00Z", "temp_tenths": 1, "setpoint_tenths": 1,
            "deadband_tenths": 1, "cool_active": False, "heat_active": True, "state": "OK", "sensor_ok": True
        })
        assert_is_instance(tr, fs_models.TelemetryRecord, "Factory should return TelemetryRecord")

        # User
        u = fs_models.create_user({"username": "abc", "password_hash": "p", "salt": "s"})
        assert_is_instance(u, fs_models.User, "Factory should return User")

        # Session
        s = fs_models.create_session({"session_id": "s1", "user_id": "u1", "username": "abc"})
        assert_is_instance(s, fs_models.Session, "Factory should return Session")

        # AuditEvent
        ae = fs_models.create_audit_event({"timestamp_ms": 1, "utc_timestamp": "Z", "event_type": "X"})
        assert_is_instance(ae, fs_models.AuditEvent, "Factory should return AuditEvent")

        # Device
        dv = fs_models.create_device({"tenant_id": "t1", "device_id": "d1"})
        assert_is_instance(dv, fs_models.Device, "Factory should return Device")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsValidationFunctions:
    def test_validate_tenant_and_device_id(self):
        assert_true(fs_models.validate_tenant_id("t1"), "valid tenant id")
        assert_false(fs_models.validate_tenant_id(""), "empty tenant id invalid")
        assert_false(fs_models.validate_tenant_id(None), "non-str invalid")
        assert_false(fs_models.validate_tenant_id("a" * 101), 
                     "tenant id >100 chars invalid")

        assert_true(fs_models.validate_device_id("d1"), "valid device id")
        assert_false(fs_models.validate_device_id(""), "empty device id invalid")
        assert_false(fs_models.validate_device_id(None), "non-str invalid")
        assert_false(fs_models.validate_device_id("a" * 101), 
                     "device id >100 chars invalid")

    def test_validate_username_role_device_status(self):
        # Username
        assert_true(fs_models.validate_username("abc"), "min 3 chars")
        assert_true(fs_models.validate_username("user.name"), "dot ok")
        assert_true(fs_models.validate_username("user-测试"), "unicode ok")
        assert_false(fs_models.validate_username("ab"), "too short")
        assert_false(fs_models.validate_username(""), "empty invalid")
        assert_false(fs_models.validate_username("user with spaces"), "spaces invalid")
        assert_true(fs_models.validate_username("a" * 50), "50 ok")
        assert_false(fs_models.validate_username("a" * 51), "51 invalid")

        # Role
        for role in ["admin", "operator", "read-only", "viewer", "guest", "super_admin", "system_admin", "READ_ONLY"]:
            assert_true(fs_models.validate_role(role), f"role {role} valid")
        assert_false(fs_models.validate_role("invalid_role"), "invalid role")

        # Device status
        for st in ["active", "inactive", "maintenance", "error", "offline", "ACTIVE"]:
            assert_true(fs_models.validate_device_status(st), f"status {st} valid")
        assert_false(fs_models.validate_device_status("unknown"), "invalid status")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsTelemetryRecord:
    def test_fs_telemetry_record_missing_fields_raise(self):
        with assert_raises(ValueError):
            fs_models.TelemetryRecord(
                tenant_id="", device_id="d1", timestamp_ms=1, utc_timestamp="Z",
                temp_tenths=1, setpoint_tenths=1, deadband_tenths=1,
                cool_active=False, heat_active=False, state="S", sensor_ok=True
            )
        with assert_raises(ValueError):
            fs_models.TelemetryRecord(
                tenant_id="t1", device_id="", timestamp_ms=1, utc_timestamp="Z",
                temp_tenths=1, setpoint_tenths=1, deadband_tenths=1,
                cool_active=False, heat_active=False, state="S", sensor_ok=True
            )
        with assert_raises(ValueError):
            fs_models.TelemetryRecord(
                tenant_id="t1", device_id="d1", timestamp_ms=0, utc_timestamp="Z",
                temp_tenths=1, setpoint_tenths=1, deadband_tenths=1,
                cool_active=False, heat_active=False, state="S", sensor_ok=True
            )


@pytest.mark.firestore
@pytest.mark.unit
class TestFsUser:
    def test_fs_user_required_fields(self):
        with assert_raises(ValueError):
            fs_models.User(username="", password_hash="p", salt="s")
        with assert_raises(ValueError):
            fs_models.User(username="u", password_hash="", salt="s")
        with assert_raises(ValueError):
            fs_models.User(username="u", password_hash="p", salt="")

    def test_fs_user_is_locked_and_admin_and_access(self):
        u1 = fs_models.User(username="u", password_hash="p", salt="s", locked_until=0, role="operator")
        assert_false(u1.is_locked, "locked_until=0 should be unlocked")
        assert_false(u1.is_admin, "operator is not admin")
        assert_true(u1.can_access_tenant("any"), "can_access_tenant returns True")

        future_ms = int(datetime.utcnow().timestamp() * 1000) + 3600 * 1000
        u2 = fs_models.User(username="u", password_hash="p", salt="s", locked_until=future_ms, role="ADMIN")
        assert_true(u2.is_locked, "future locked_until should lock user")
        assert_true(u2.is_admin, "ADMIN should be admin")


@pytest.mark.firestore
@pytest.mark.unit
class TestFsSession:
    def test_fs_session_required_fields(self):
        with assert_raises(ValueError):
            fs_models.Session(session_id="", user_id="u", username="n")
        with assert_raises(ValueError):
            fs_models.Session(session_id="s", user_id="", username="n")
        with assert_raises(ValueError):
            fs_models.Session(session_id="s", user_id="u", username="")

    def test_fs_session_expiry_and_valid(self):
        now_ms = int(datetime.utcnow().timestamp() * 1000)
        s_valid = fs_models.Session(session_id="s1", user_id="u1", username="n1", expires_at=now_ms + 1000)
        assert_false(s_valid.is_expired, "future expiry should not be expired")
        assert_true(s_valid.is_valid, "valid when not expired")

        s_exp = fs_models.Session(session_id="s2", user_id="u2", username="n2", expires_at=now_ms - 1)
        assert_true(s_exp.is_expired, "past expiry should be expired")
        assert_false(s_exp.is_valid, "invalid when expired")

    def test_fs_session_extend(self):
        base = 1000
        s = fs_models.Session(session_id="s1", user_id="u1", username="n1", expires_at=base)
        s.extend_session(2)
        assert_equals(s.expires_at, base + 2000, "extend_session adds seconds in ms")
