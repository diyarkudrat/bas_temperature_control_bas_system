"""
Unit tests for authentication exceptions using pytest.
"""

import pytest

from auth.exceptions import AuthError, SessionError, MFAError, UserError, ConfigurationError
from tests.utils.assertions import assert_equals, assert_is_instance


@pytest.mark.auth
@pytest.mark.unit
class TestAuthExceptions:
    """Test authentication exceptions with 100% coverage."""

    def test_auth_error(self):
        """Test AuthError exception."""
        error = AuthError("Test error")
        assert_equals(str(error), "Test error")
        assert_is_instance(error, Exception)

    def test_session_error(self):
        """Test SessionError exception."""
        error = SessionError("Session error")
        assert_equals(str(error), "Session error")
        assert_is_instance(error, AuthError)

    def test_mfa_error(self):
        """Test MFAError exception."""
        error = MFAError("MFA error")
        assert_equals(str(error), "MFA error")
        assert_is_instance(error, AuthError)

    def test_user_error(self):
        """Test UserError exception."""
        error = UserError("User error")
        assert_equals(str(error), "User error")
        assert_is_instance(error, AuthError)

    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        error = ConfigurationError("Config error")
        assert_equals(str(error), "Config error")
        assert_is_instance(error, AuthError)
