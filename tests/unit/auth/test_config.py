"""
Unit tests for AuthConfig class using pytest.
"""

import json
import pytest
from unittest.mock import patch

from auth.config import AuthConfig
from tests.utils.assertions import assert_equals, assert_true, assert_false


@pytest.mark.auth
@pytest.mark.unit
class TestAuthConfig:
    """Test AuthConfig class with 100% coverage."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AuthConfig()
        assert_true(config.auth_enabled)
        assert_equals(config.auth_mode, "user_password_mfa")
        assert_equals(config.session_timeout, 1800)
        assert_equals(config.max_concurrent_sessions, 3)
        assert_equals(config.mfa_code_expiry, 300)
        assert_equals(config.max_login_attempts, 5)
        assert_equals(config.password_min_length, 12)
        assert_equals(config.rate_limit_per_ip, 100)
        assert_equals(config.rate_limit_per_user, 50)
        assert_equals(config.auth_attempts_per_15min, 5)
        assert config.twilio_account_sid is None
        assert config.twilio_auth_token is None
        assert config.twilio_from_number is None

    def test_from_env(self):
        """Test loading configuration from environment variables."""
        with patch.dict('os.environ', {
            'BAS_AUTH_ENABLED': 'false',
            'BAS_AUTH_MODE': 'shadow',
            'BAS_SESSION_TIMEOUT': '3600',
            'BAS_MAX_CONCURRENT_SESSIONS': '5',
            'BAS_MAX_LOGIN_ATTEMPTS': '3',
            'BAS_LOCKOUT_DURATION': '1800',
            'TWILIO_ACCOUNT_SID': 'test_sid',
            'TWILIO_AUTH_TOKEN': 'test_token',
            'TWILIO_FROM_NUMBER': '+1234567890'
        }):
            config = AuthConfig.from_env()
            assert_false(config.auth_enabled)
            assert_equals(config.auth_mode, 'shadow')
            assert_equals(config.session_timeout, 3600)
            assert_equals(config.max_concurrent_sessions, 5)
            assert_equals(config.max_login_attempts, 3)
            assert_equals(config.lockout_duration, 1800)
            assert_equals(config.twilio_account_sid, 'test_sid')
            assert_equals(config.twilio_auth_token, 'test_token')
            assert_equals(config.twilio_from_number, '+1234567890')

    def test_from_file_success(self, temp_config_file):
        """Test loading configuration from file successfully."""
        config_data = {
            'auth_enabled': False,
            'auth_mode': 'enforced',
            'session_timeout': 3600,
            'max_concurrent_sessions': 5,
            'twilio_account_sid': 'test_sid',
            'twilio_auth_token': 'test_token',
            'twilio_from_number': '+1234567890'
        }
        
        with open(temp_config_file, 'w') as f:
            json.dump(config_data, f)
        
        config = AuthConfig.from_file(temp_config_file)
        assert_false(config.auth_enabled)
        assert_equals(config.auth_mode, 'enforced')
        assert_equals(config.session_timeout, 3600)
        assert_equals(config.max_concurrent_sessions, 5)
        assert_equals(config.twilio_account_sid, 'test_sid')

    def test_from_file_not_found(self):
        """Test loading configuration from non-existent file."""
        config = AuthConfig.from_file('nonexistent.json')
        # Should return default config
        assert_true(config.auth_enabled)
        assert_equals(config.auth_mode, "user_password_mfa")

    def test_from_file_invalid_json(self, temp_config_file):
        """Test loading configuration from invalid JSON file."""
        with open(temp_config_file, 'w') as f:
            f.write('invalid json content')
        
        config = AuthConfig.from_file(temp_config_file)
        # Should return default config
        assert_true(config.auth_enabled)

    def test_validate_auth_disabled(self):
        """Test validation when auth is disabled."""
        config = AuthConfig(auth_enabled=False)
        assert_true(config.validate())

    def test_validate_auth_mode_disabled(self):
        """Test validation when auth mode is disabled."""
        config = AuthConfig(auth_mode="disabled")
        assert_true(config.validate())

    def test_validate_twilio_incomplete(self):
        """Test validation with incomplete Twilio configuration."""
        config = AuthConfig(
            auth_mode="enforced",
            twilio_account_sid="test",
            twilio_auth_token=None,
            twilio_from_number="+1234567890"
        )
        assert_false(config.validate())

    def test_validate_session_timeout_too_short(self):
        """Test validation with session timeout too short."""
        config = AuthConfig(session_timeout=100)  # Less than 300 seconds
        # Should still validate but log warning
        assert_true(config.validate())

    def test_validate_max_concurrent_sessions_too_low(self):
        """Test validation with max concurrent sessions too low."""
        config = AuthConfig(max_concurrent_sessions=0)
        # Should still validate but log warning
        assert_true(config.validate())

    def test_validate_password_min_length_too_low(self):
        """Test validation with password minimum length too low."""
        config = AuthConfig(password_min_length=6)
        # Should still validate but log warning
        assert_true(config.validate())
