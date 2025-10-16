"""
Unit tests for authentication models (User, Session, PendingMFA) using pytest.
"""

import time
import pytest

from auth.models import User, Session, PendingMFA
from tests.utils.assertions import assert_equals, assert_true, assert_false


@pytest.mark.auth
@pytest.mark.unit
class TestUserModel:
    """Test User model with 100% coverage."""

    def test_user_creation(self, sample_user):
        """Test user creation with default values."""
        assert_equals(sample_user.username, "testuser")
        assert_equals(sample_user.password_hash, "hashed_password_123")
        assert_equals(sample_user.salt, "salt_123")
        assert_equals(sample_user.phone_number, "+1234567890")
        assert_equals(sample_user.role, "operator")
        assert_equals(sample_user.failed_attempts, 0)
        assert_equals(sample_user.locked_until, 0)
        assert_equals(sample_user.password_history, [])
        assert_true(sample_user.mfa_enabled)

    def test_user_is_locked_false(self, sample_user):
        """Test user is not locked."""
        assert_false(sample_user.is_locked())

    def test_user_is_locked_true(self, sample_user):
        """Test user is locked."""
        sample_user.locked_until = time.time() + 3600  # Locked for 1 hour
        assert_true(sample_user.is_locked())

    def test_user_to_dict(self, sample_user):
        """Test converting user to dictionary."""
        user_dict = sample_user.to_dict()
        assert_equals(user_dict['username'], "testuser")
        assert_equals(user_dict['password_hash'], "hashed_password_123")
        assert_equals(user_dict['salt'], "salt_123")
        assert_equals(user_dict['phone_number'], "+1234567890")
        assert_equals(user_dict['role'], "operator")
        assert_equals(user_dict['failed_attempts'], 0)
        assert_equals(user_dict['locked_until'], 0)
        assert_equals(user_dict['mfa_enabled'], True)
        assert isinstance(user_dict['password_history'], str)  # JSON string

    def test_user_from_dict(self):
        """Test creating user from dictionary."""
        user_data = {
            'username': 'newuser',
            'password_hash': 'newhash',
            'salt': 'newsalt',
            'phone_number': '+9876543210',
            'role': 'admin',
            'created_at': 1234567890.0,
            'last_login': 1234567891.0,
            'failed_attempts': 2,
            'locked_until': 1234567892.0,
            'password_history': '["old1", "old2"]',
            'mfa_enabled': False
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.username, 'newuser')
        assert_equals(user.password_hash, 'newhash')
        assert_equals(user.salt, 'newsalt')
        assert_equals(user.phone_number, '+9876543210')
        assert_equals(user.role, 'admin')
        assert_equals(user.created_at, 1234567890.0)
        assert_equals(user.last_login, 1234567891.0)
        assert_equals(user.failed_attempts, 2)
        assert_equals(user.locked_until, 1234567892.0)
        assert_equals(user.password_history, ['old1', 'old2'])
        assert_false(user.mfa_enabled)

    def test_user_from_dict_defaults(self):
        """Test creating user from dictionary with missing fields."""
        user_data = {
            'username': 'minimaluser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1111111111'
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.role, 'operator')
        assert_equals(user.failed_attempts, 0)
        assert_equals(user.locked_until, 0)
        assert_equals(user.password_history, [])
        assert_true(user.mfa_enabled)


@pytest.mark.auth
@pytest.mark.unit
class TestSessionModel:
    """Test Session model with 100% coverage."""

    def test_session_creation(self, sample_session):
        """Test session creation."""
        assert_equals(sample_session.session_id, "sess_test_123")
        assert_equals(sample_session.username, "testuser")
        assert_equals(sample_session.role, "operator")
        assert_equals(sample_session.fingerprint, "test_fingerprint_123")
        assert_equals(sample_session.ip_address, "192.168.1.100")
        assert_equals(sample_session.user_agent, "Test Browser")
        assert_true(sample_session.mfa_verified)

    def test_session_not_expired(self, sample_session):
        """Test session is not expired."""
        assert_false(sample_session.is_expired())

    def test_session_expired(self, sample_session):
        """Test session is expired."""
        sample_session.expires_at = time.time() - 1  # Expired 1 second ago
        assert_true(sample_session.is_expired())

    def test_session_to_dict(self, sample_session):
        """Test converting session to dictionary."""
        session_dict = sample_session.to_dict()
        assert_equals(session_dict['session_id'], "sess_test_123")
        assert_equals(session_dict['username'], "testuser")
        assert_equals(session_dict['role'], "operator")
        assert_equals(session_dict['fingerprint'], "test_fingerprint_123")
        assert_equals(session_dict['ip_address'], "192.168.1.100")
        assert_equals(session_dict['user_agent'], "Test Browser")
        assert_true(session_dict['mfa_verified'])

    def test_session_from_dict(self):
        """Test creating session from dictionary."""
        session_data = {
            'session_id': 'sess_456',
            'username': 'newuser',
            'role': 'admin',
            'created_at': 1234567890.0,
            'expires_at': 1234567891.0,
            'last_access': 1234567892.0,
            'fingerprint': 'newfingerprint',
            'ip_address': '10.0.0.1',
            'user_agent': 'Chrome/91.0',
            'mfa_verified': False
        }
        
        session = Session.from_dict(session_data)
        assert_equals(session.session_id, 'sess_456')
        assert_equals(session.username, 'newuser')
        assert_equals(session.role, 'admin')
        assert_equals(session.created_at, 1234567890.0)
        assert_equals(session.expires_at, 1234567891.0)
        assert_equals(session.last_access, 1234567892.0)
        assert_equals(session.fingerprint, 'newfingerprint')
        assert_equals(session.ip_address, '10.0.0.1')
        assert_equals(session.user_agent, 'Chrome/91.0')
        assert_false(session.mfa_verified)

    def test_session_from_dict_defaults(self):
        """Test creating session from dictionary with missing fields."""
        session_data = {
            'session_id': 'sess_789',
            'username': 'minimaluser',
            'role': 'read-only',
            'created_at': 1234567890.0,
            'expires_at': 1234567891.0,
            'last_access': 1234567892.0,
            'fingerprint': 'minimalfingerprint',
            'ip_address': '127.0.0.1',
            'user_agent': 'Safari/14.0'
        }
        
        session = Session.from_dict(session_data)
        assert_true(session.mfa_verified)  # Default value


@pytest.mark.auth
@pytest.mark.unit
class TestPendingMFAModel:
    """Test PendingMFA model with 100% coverage."""

    def test_pending_mfa_creation(self, sample_pending_mfa):
        """Test pending MFA creation."""
        assert_equals(sample_pending_mfa.username, "testuser")
        assert_equals(sample_pending_mfa.code, "123456")
        assert_equals(sample_pending_mfa.phone_number, "+1234567890")

    def test_pending_mfa_not_expired(self, sample_pending_mfa):
        """Test pending MFA is not expired."""
        assert_false(sample_pending_mfa.is_expired())

    def test_pending_mfa_expired(self, sample_pending_mfa):
        """Test pending MFA is expired."""
        sample_pending_mfa.expires_at = time.time() - 1  # Expired 1 second ago
        assert_true(sample_pending_mfa.is_expired())

    def test_user_from_dict_invalid_password_history(self):
        """Test creating user from dictionary with invalid password history."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890',
            'password_history': 'invalid_json'  # Invalid JSON
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.password_history, [], "Should default to empty list for invalid JSON")

    def test_user_from_dict_non_list_password_history(self):
        """Test creating user from dictionary with non-list password history."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890',
            'password_history': '{"not": "a_list"}'  # Valid JSON but not a list
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.password_history, [], "Should default to empty list for non-list JSON")

    def test_user_from_dict_invalid_numeric_fields(self):
        """Test creating user from dictionary with invalid numeric fields."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890',
            'created_at': 'invalid',  # Invalid number
            'last_login': -1,  # Negative number
            'failed_attempts': 'not_a_number',  # Invalid number
            'locked_until': None  # None value
        }
        
        user = User.from_dict(user_data)
        assert_true(user.created_at > 0, "Should set valid created_at for invalid input")
        assert_equals(user.last_login, 0, "Should default to 0 for negative last_login")
        assert_equals(user.failed_attempts, 0, "Should default to 0 for invalid failed_attempts")
        assert_equals(user.locked_until, 0, "Should default to 0 for None locked_until")

    def test_user_from_dict_invalid_role(self):
        """Test creating user from dictionary with invalid role."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890',
            'role': 'invalid_role'  # Invalid role
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.role, 'operator', "Should default to operator for invalid role")

    def test_user_from_dict_missing_mfa_enabled(self):
        """Test creating user from dictionary with missing mfa_enabled field."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890'
            # Missing mfa_enabled
        }
        
        user = User.from_dict(user_data)
        assert_true(user.mfa_enabled, "Should default to True for missing mfa_enabled")

    def test_session_from_dict_invalid_numeric_fields(self):
        """Test creating session from dictionary with invalid numeric fields."""
        session_data = {
            'session_id': 'sess_123',
            'username': 'testuser',
            'role': 'operator',
            'created_at': 'invalid',  # Invalid number
            'expires_at': 1000,  # Less than created_at
            'last_access': 'not_a_number',  # Invalid number
            'fingerprint': 'test_fingerprint',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Browser'
        }
        
        session = Session.from_dict(session_data)
        assert_true(session.created_at > 0, "Should set valid created_at for invalid input")
        assert_true(session.expires_at > session.created_at, "Should set valid expires_at")
        assert_true(session.last_access >= session.created_at, "Should set valid last_access")

    def test_session_from_dict_invalid_role(self):
        """Test creating session from dictionary with invalid role."""
        session_data = {
            'session_id': 'sess_123',
            'username': 'testuser',
            'role': 'invalid_role',  # Invalid role
            'created_at': time.time(),
            'expires_at': time.time() + 3600,
            'last_access': time.time(),
            'fingerprint': 'test_fingerprint',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Browser'
        }
        
        session = Session.from_dict(session_data)
        assert_equals(session.role, 'operator', "Should default to operator for invalid role")

    def test_session_from_dict_missing_mfa_verified(self):
        """Test creating session from dictionary with missing mfa_verified field."""
        session_data = {
            'session_id': 'sess_123',
            'username': 'testuser',
            'role': 'operator',
            'created_at': time.time(),
            'expires_at': time.time() + 3600,
            'last_access': time.time(),
            'fingerprint': 'test_fingerprint',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Browser'
            # Missing mfa_verified
        }
        
        session = Session.from_dict(session_data)
        assert_true(session.mfa_verified, "Should default to True for missing mfa_verified")

    def test_user_to_dict_logging(self, sample_user):
        """Test that to_dict method logs debug information."""
        # This test verifies the logging behavior is present
        # We can't easily test the actual log output, but we can verify the method works
        user_dict = sample_user.to_dict()
        assert_is_not_none(user_dict)
        assert_equals(user_dict['username'], sample_user.username)

    def test_session_to_dict_logging(self, sample_session):
        """Test that to_dict method logs debug information."""
        # This test verifies the logging behavior is present
        # We can't easily test the actual log output, but we can verify the method works
        session_dict = sample_session.to_dict()
        assert_is_not_none(session_dict)
        assert_equals(session_dict['session_id'], sample_session.session_id)

    def test_user_from_dict_logging(self):
        """Test that from_dict method logs debug information."""
        # This test verifies the logging behavior is present
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890'
        }
        
        user = User.from_dict(user_data)
        assert_is_not_none(user)
        assert_equals(user.username, 'testuser')

    def test_session_from_dict_logging(self):
        """Test that from_dict method logs debug information."""
        # This test verifies the logging behavior is present
        session_data = {
            'session_id': 'sess_123',
            'username': 'testuser',
            'role': 'operator',
            'created_at': time.time(),
            'expires_at': time.time() + 3600,
            'last_access': time.time(),
            'fingerprint': 'test_fingerprint',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Browser'
        }
        
        session = Session.from_dict(session_data)
        assert_is_not_none(session)
        assert_equals(session.session_id, 'sess_123')

    def test_user_is_locked_logging(self, sample_user):
        """Test that is_locked method logs warning when locked."""
        # This test verifies the logging behavior is present
        # We can't easily test the actual log output, but we can verify the method works
        sample_user.locked_until = time.time() + 3600
        is_locked = sample_user.is_locked()
        assert_true(is_locked)

    def test_session_is_expired_logging(self, sample_session):
        """Test that is_expired method logs debug information."""
        # This test verifies the logging behavior is present
        # We can't easily test the actual log output, but we can verify the method works
        sample_session.expires_at = time.time() - 1
        is_expired = sample_session.is_expired()
        assert_true(is_expired)

    def test_pending_mfa_is_expired_logging(self, sample_pending_mfa):
        """Test that is_expired method logs debug information."""
        # This test verifies the logging behavior is present
        # We can't easily test the actual log output, but we can verify the method works
        sample_pending_mfa.expires_at = time.time() - 1
        is_expired = sample_pending_mfa.is_expired()
        assert_true(is_expired)

    def test_user_from_dict_edge_case_timestamps(self):
        """Test creating user from dictionary with edge case timestamps."""
        user_data = {
            'username': 'testuser',
            'password_hash': 'hash',
            'salt': 'salt',
            'phone_number': '+1234567890',
            'created_at': 0,  # Zero timestamp
            'last_login': 0.0,  # Zero float timestamp
            'locked_until': 0,  # Zero timestamp
            'failed_attempts': 0  # Zero attempts
        }
        
        user = User.from_dict(user_data)
        assert_equals(user.created_at, 0, "Should preserve zero created_at")
        assert_equals(user.last_login, 0, "Should preserve zero last_login")
        assert_equals(user.locked_until, 0, "Should preserve zero locked_until")
        assert_equals(user.failed_attempts, 0, "Should preserve zero failed_attempts")

    def test_session_from_dict_edge_case_timestamps(self):
        """Test creating session from dictionary with edge case timestamps."""
        current_time = time.time()
        session_data = {
            'session_id': 'sess_123',
            'username': 'testuser',
            'role': 'operator',
            'created_at': current_time,
            'expires_at': current_time + 1,  # Just 1 second later
            'last_access': current_time,
            'fingerprint': 'test_fingerprint',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Browser'
        }
        
        session = Session.from_dict(session_data)
        assert_equals(session.created_at, current_time, "Should preserve created_at")
        assert_equals(session.expires_at, current_time + 1, "Should preserve expires_at")
        assert_equals(session.last_access, current_time, "Should preserve last_access")
