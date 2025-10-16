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
