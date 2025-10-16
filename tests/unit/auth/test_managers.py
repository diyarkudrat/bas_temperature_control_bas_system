"""
Unit tests for authentication managers (UserManager, SessionManager, MFAManager) using pytest.
"""

import time
import pytest

from auth.config import AuthConfig
from auth.managers import UserManager, SessionManager, MFAManager
from auth.exceptions import AuthError
from tests.utils.assertions import assert_equals, assert_true, assert_false, assert_is_not_none, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestUserManager:
    """Test UserManager with 100% coverage."""

    def test_create_user_success(self, user_manager):
        """Test successful user creation."""
        user = user_manager.create_user(
            "newuser", "ValidPassword123!", "+1234567890", "operator"
        )
        assert_equals(user.username, "newuser")
        assert_equals(user.phone_number, "+1234567890")
        assert_equals(user.role, "operator")

    def test_create_user_weak_password(self, user_manager):
        """Test user creation with weak password."""
        with assert_raises(AuthError):
            user_manager.create_user(
                "newuser", "weak", "+1234567890", "operator"
            )

    def test_create_user_already_exists(self, user_manager):
        """Test creating user that already exists."""
        # Create first user
        user_manager.create_user(
            "existinguser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        # Try to create same user again
        with assert_raises(AuthError):
            user_manager.create_user(
                "existinguser", "AnotherPassword123!", "+9876543210", "admin"
            )

    def test_authenticate_user_success(self, user_manager):
        """Test successful user authentication."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        # Authenticate
        user = user_manager.authenticate_user("testuser", "ValidPassword123!")
        assert_is_not_none(user)
        assert_equals(user.username, "testuser")

    def test_authenticate_user_wrong_password(self, user_manager):
        """Test authentication with wrong password."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        # Try wrong password
        user = user_manager.authenticate_user("testuser", "WrongPassword123!")
        assert user is None

    def test_authenticate_user_not_found(self, user_manager):
        """Test authentication for non-existent user."""
        user = user_manager.authenticate_user("nonexistent", "SomePassword123!")
        assert user is None

    def test_authenticate_user_locked(self, user_manager):
        """Test authentication for locked user."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        # Lock the user
        user = user_manager.get_user("testuser")
        user.locked_until = time.time() + 3600  # Locked for 1 hour
        user_manager._store_user(user)
        
        # Try to authenticate locked user
        auth_user = user_manager.authenticate_user("testuser", "ValidPassword123!")
        assert auth_user is None

    def test_get_user_found(self, user_manager):
        """Test getting existing user."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        user = user_manager.get_user("testuser")
        assert_is_not_none(user)
        assert_equals(user.username, "testuser")

    def test_get_user_not_found(self, user_manager):
        """Test getting non-existent user."""
        user = user_manager.get_user("nonexistent")
        assert user is None

    def test_update_last_login(self, user_manager):
        """Test updating user's last login time."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "+1234567890", "operator"
        )
        
        # Update last login
        user_manager.update_last_login("testuser")
        
        # Verify update
        user = user_manager.get_user("testuser")
        assert_true(user.last_login > 0)


@pytest.mark.auth
@pytest.mark.unit
class TestSessionManager:
    """Test SessionManager with 100% coverage."""

    def test_create_session(self, session_manager, mock_request):
        """Test session creation."""
        session = session_manager.create_session("testuser", "operator", mock_request)
        assert_equals(session.username, "testuser")
        assert_equals(session.role, "operator")
        assert_is_not_none(session.session_id)
        assert_is_not_none(session.fingerprint)

    def test_validate_session_success(self, session_manager, mock_request):
        """Test successful session validation."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Validate session
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert_is_not_none(validated_session)
        assert_equals(validated_session.session_id, session.session_id)

    def test_validate_session_not_found(self, session_manager, mock_request):
        """Test session validation for non-existent session."""
        session = session_manager.validate_session("nonexistent", mock_request)
        assert session is None

    def test_validate_session_expired(self, session_manager, mock_request):
        """Test session validation for expired session."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Manually expire the session
        session.expires_at = time.time() - 1
        session_manager.sessions[session.session_id] = session
        
        # Try to validate expired session
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert validated_session is None

    def test_validate_session_fingerprint_mismatch(self, session_manager, mock_request):
        """Test session validation with fingerprint mismatch."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Change request fingerprint
        mock_request.headers['User-Agent'] = 'Chrome/91.0'
        
        # Try to validate with different fingerprint
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert validated_session is None

    def test_invalidate_session(self, session_manager, mock_request):
        """Test session invalidation."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        session_id = session.session_id
        
        # Invalidate session
        session_manager.invalidate_session(session_id)
        
        # Try to get invalidated session
        invalidated_session = session_manager.get_session(session_id)
        assert invalidated_session is None

    def test_update_last_access(self, session_manager, mock_request):
        """Test updating session last access time."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        session_id = session.session_id
        original_access = session.last_access
        
        # Update last access
        time.sleep(0.1)  # Small delay to ensure time difference
        session_manager.update_last_access(session_id)
        
        # Verify update
        updated_session = session_manager.get_session(session_id)
        assert_true(updated_session.last_access > original_access)


@pytest.mark.auth
@pytest.mark.unit
class TestMFAManager:
    """Test MFAManager with 100% coverage."""

    def test_generate_code(self, mfa_manager):
        """Test MFA code generation."""
        code = mfa_manager.generate_code("testuser")
        assert_equals(len(code), mfa_manager.config.mfa_code_length)
        assert_true(code.isdigit())

    def test_verify_code_success(self, mfa_manager):
        """Test successful MFA code verification."""
        code = mfa_manager.generate_code("testuser")
        is_valid = mfa_manager.verify_code("testuser", code)
        assert_true(is_valid)

    def test_verify_code_wrong_code(self, mfa_manager):
        """Test MFA code verification with wrong code."""
        mfa_manager.generate_code("testuser")
        is_valid = mfa_manager.verify_code("testuser", "000000")
        assert_false(is_valid)

    def test_verify_code_no_pending(self, mfa_manager):
        """Test MFA code verification with no pending MFA."""
        is_valid = mfa_manager.verify_code("nonexistent", "123456")
        assert_false(is_valid)

    def test_verify_code_expired(self, mfa_manager):
        """Test MFA code verification with expired code."""
        # Generate code
        mfa_manager.generate_code("testuser")
        
        # Manually expire the code
        pending = mfa_manager.pending_mfa["testuser"]
        pending.expires_at = time.time() - 1
        mfa_manager.pending_mfa["testuser"] = pending
        
        # Try to verify expired code
        is_valid = mfa_manager.verify_code("testuser", pending.code)
        assert_false(is_valid)

    def test_get_pending(self, mfa_manager):
        """Test getting pending MFA."""
        mfa_manager.generate_code("testuser")
        pending = mfa_manager.get_pending("testuser")
        assert_is_not_none(pending)
        assert_equals(pending.username, "testuser")

    def test_get_pending_none(self, mfa_manager):
        """Test getting pending MFA for non-existent user."""
        pending = mfa_manager.get_pending("nonexistent")
        assert pending is None

    def test_clear_pending(self, mfa_manager):
        """Test clearing pending MFA."""
        mfa_manager.generate_code("testuser")
        assert_is_not_none(mfa_manager.get_pending("testuser"))
        
        mfa_manager.clear_pending("testuser")
        assert mfa_manager.get_pending("testuser") is None
