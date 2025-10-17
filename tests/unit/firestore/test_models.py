"""Tests for Domain Models."""

import pytest
import time
import uuid
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    MockBaseEntity as BaseEntity, MockTelemetryRecord as TelemetryRecord, MockUser as User, 
    MockSession as Session, MockAuditEvent as AuditEvent, MockDevice as Device,
    create_mock_telemetry_record as create_telemetry_record, create_mock_user as create_user, 
    create_mock_session as create_session, create_mock_audit_event as create_audit_event, 
    create_mock_device as create_device, validate_mock_username as validate_username, 
    validate_mock_role as validate_role
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestBaseEntity:
    """Test cases for BaseEntity."""
    
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


@pytest.mark.auth
@pytest.mark.unit
class TestTelemetryRecord:
    """Test cases for TelemetryRecord."""
    
    def test_telemetry_record_init_success(self):
        """Test successful TelemetryRecord initialization."""
        record = TelemetryRecord(
            tenant_id="tenant_123",
            device_id="device_456",
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
        
        assert_equals(record.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(record.device_id, "device_456", "Should set device_id")
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
                device_id="device_456",
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
                tenant_id="tenant_123",
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
                tenant_id="tenant_123",
                device_id="device_456",
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
            tenant_id="tenant_123",
            device_id="device_456",
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
        
        assert_equals(result['tenant_id'], "tenant_123", "Should include tenant_id")
        assert_equals(result['device_id'], "device_456", "Should include device_id")
        assert_equals(result['timestamp_ms'], 1640995200000, "Should include timestamp_ms")
        assert_equals(result['temp_tenths'], 230, "Should include temp_tenths")
        assert_false(result['cool_active'], "Should include cool_active")
        assert_true(result['heat_active'], "Should include heat_active")
    
    def test_telemetry_record_from_dict(self):
        """Test TelemetryRecord from_dict method."""
        data = {
            'tenant_id': 'tenant_123',
            'device_id': 'device_456',
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
        
        assert_equals(record.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(record.device_id, "device_456", "Should set device_id")
        assert_equals(record.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(record.temp_tenths, 230, "Should set temp_tenths")
        assert_false(record.cool_active, "Should set cool_active")
        assert_true(record.heat_active, "Should set heat_active")
    
    def test_create_telemetry_record(self):
        """Test create_telemetry_record factory function."""
        data = {
            'tenant_id': 'tenant_123',
            'device_id': 'device_456',
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
        assert_equals(record.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(record.device_id, "device_456", "Should set device_id")


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
        assert_true(user.can_access_tenant("tenant_123"), "Should allow access to any tenant")
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
        
        result = user.to_dict()
        
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
            session_id="sess_123",
            user_id="user_456",
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
        
        assert_equals(session.session_id, "sess_123", "Should set session_id")
        assert_equals(session.user_id, "user_456", "Should set user_id")
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
            session_id="sess_123",
            user_id="user_456",
            username="testuser",
            expires_at=future_time
        )
        
        assert_false(session.is_expired, "Should not be expired")
    
    def test_session_is_expired_expired(self):
        """Test Session is_expired property when expired."""
        past_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        
        session = Session(
            session_id="sess_123",
            user_id="user_456",
            username="testuser",
            expires_at=past_time
        )
        
        assert_true(session.is_expired, "Should be expired")
    
    def test_session_is_valid_valid(self):
        """Test Session is_valid property when valid."""
        future_time = int(time.time() * 1000) + 3600000  # 1 hour from now
        
        session = Session(
            session_id="sess_123",
            user_id="user_456",
            username="testuser",
            expires_at=future_time
        )
        
        assert_true(session.is_valid, "Should be valid")
    
    def test_session_is_valid_invalid(self):
        """Test Session is_valid property when invalid."""
        past_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        
        session = Session(
            session_id="sess_123",
            user_id="user_456",
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
            session_id="sess_123",
            user_id="user_456",
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
        
        result = session.to_dict()
        
        assert_equals(result['session_id'], "sess_123", "Should include session_id")
        assert_equals(result['user_id'], "user_456", "Should include user_id")
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
            'session_id': 'sess_123',
            'user_id': 'user_456',
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
        
        assert_equals(session.session_id, "sess_123", "Should set session_id")
        assert_equals(session.user_id, "user_456", "Should set user_id")
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
            'session_id': 'sess_123',
            'user_id': 'user_456',
            'username': 'testuser',
            'role': 'operator'
        }
        
        session = create_session(data)
        
        assert_is_instance(session, Session, "Should return Session instance")
        assert_equals(session.session_id, "sess_123", "Should set session_id")
        assert_equals(session.user_id, "user_456", "Should set user_id")


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
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            details={"session_id": "sess_456"},
            tenant_id="tenant_789"
        )
        
        assert_equals(event.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(event.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(event.event_type, "LOGIN_SUCCESS", "Should set event_type")
        assert_equals(event.user_id, "user_123", "Should set user_id")
        assert_equals(event.username, "testuser", "Should set username")
        assert_equals(event.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(event.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(event.details, {"session_id": "sess_456"}, "Should set details")
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
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            details={"session_id": "sess_456"},
            tenant_id="tenant_789"
        )
        
        result = event.to_dict()
        
        assert_equals(result['timestamp_ms'], 1640995200000, "Should include timestamp_ms")
        assert_equals(result['utc_timestamp'], "2022-01-01T00:00:00Z", "Should include utc_timestamp")
        assert_equals(result['event_type'], "LOGIN_SUCCESS", "Should include event_type")
        assert_equals(result['user_id'], "user_123", "Should include user_id")
        assert_equals(result['username'], "testuser", "Should include username")
        assert_equals(result['ip_address'], "192.168.1.100", "Should include ip_address")
        assert_equals(result['user_agent'], "Mozilla/5.0", "Should include user_agent")
        assert_equals(result['details'], {"session_id": "sess_456"}, "Should include details")
        assert_equals(result['tenant_id'], "tenant_789", "Should include tenant_id")
    
    def test_audit_event_from_dict(self):
        """Test AuditEvent from_dict method."""
        data = {
            'timestamp_ms': 1640995200000,
            'utc_timestamp': '2022-01-01T00:00:00Z',
            'event_type': 'LOGIN_SUCCESS',
            'user_id': 'user_123',
            'username': 'testuser',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0',
            'details': {'session_id': 'sess_456'},
            'tenant_id': 'tenant_789'
        }
        
        event = AuditEvent.from_dict(data)
        
        assert_equals(event.timestamp_ms, 1640995200000, "Should set timestamp_ms")
        assert_equals(event.utc_timestamp, "2022-01-01T00:00:00Z", "Should set utc_timestamp")
        assert_equals(event.event_type, "LOGIN_SUCCESS", "Should set event_type")
        assert_equals(event.user_id, "user_123", "Should set user_id")
        assert_equals(event.username, "testuser", "Should set username")
        assert_equals(event.ip_address, "192.168.1.100", "Should set ip_address")
        assert_equals(event.user_agent, "Mozilla/5.0", "Should set user_agent")
        assert_equals(event.details, {"session_id": "sess_456"}, "Should set details")
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
            tenant_id="tenant_123",
            device_id="device_456",
            metadata={"location": "Building A", "model": "Thermostat V2"},
            status="active"
        )
        
        assert_equals(device.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(device.device_id, "device_456", "Should set device_id")
        assert_equals(device.metadata, {"location": "Building A", "model": "Thermostat V2"}, "Should set metadata")
        assert_equals(device.status, "active", "Should set status")
    
    def test_device_init_defaults(self):
        """Test Device initialization with defaults."""
        device = Device(
            tenant_id="tenant_123",
            device_id="device_456"
        )
        
        assert_equals(device.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(device.device_id, "device_456", "Should set device_id")
        assert_equals(device.metadata, {}, "Should set default empty metadata")
        assert_equals(device.status, "active", "Should set default status")
    
    def test_device_to_dict(self):
        """Test Device to_dict method."""
        device = Device(
            tenant_id="tenant_123",
            device_id="device_456",
            metadata={"location": "Building A", "model": "Thermostat V2"},
            status="active"
        )
        
        result = device.to_dict()
        
        assert_equals(result['tenant_id'], "tenant_123", "Should include tenant_id")
        assert_equals(result['device_id'], "device_456", "Should include device_id")
        assert_equals(result['metadata'], {"location": "Building A", "model": "Thermostat V2"}, "Should include metadata")
        assert_equals(result['status'], "active", "Should include status")
    
    def test_device_from_dict(self):
        """Test Device from_dict method."""
        data = {
            'tenant_id': 'tenant_123',
            'device_id': 'device_456',
            'metadata': {'location': 'Building A', 'model': 'Thermostat V2'},
            'status': 'active'
        }
        
        device = Device.from_dict(data)
        
        assert_equals(device.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(device.device_id, "device_456", "Should set device_id")
        assert_equals(device.metadata, {"location": "Building A", "model": "Thermostat V2"}, "Should set metadata")
        assert_equals(device.status, "active", "Should set status")
    
    def test_create_device(self):
        """Test create_device factory function."""
        data = {
            'tenant_id': 'tenant_123',
            'device_id': 'device_456',
            'metadata': {'location': 'Building A'},
            'status': 'active'
        }
        
        device = create_device(data)
        
        assert_is_instance(device, Device, "Should return Device instance")
        assert_equals(device.tenant_id, "tenant_123", "Should set tenant_id")
        assert_equals(device.device_id, "device_456", "Should set device_id")


@pytest.mark.auth
@pytest.mark.unit
class TestValidationFunctions:
    """Test cases for validation functions."""
    
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
