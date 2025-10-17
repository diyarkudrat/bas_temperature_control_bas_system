"""Unit tests for authentication configuration validation."""

import pytest
import tempfile
import json
import os
from unittest.mock import patch, Mock

# Add server directory to path for imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'server'))

from auth.config import AuthConfig
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none


@pytest.mark.auth
@pytest.mark.unit
class TestAuthConfigValidation:
    """Test authentication configuration validation with comprehensive coverage."""

    def test_default_config_creation(self):
        """Test default configuration creation."""
        config = AuthConfig()
        
        # Test default values
        assert_true(config.auth_enabled)
        assert_equals(config.auth_mode, "user_password")
        assert_false(config.use_firestore_telemetry)
        assert_false(config.use_firestore_auth)
        assert_false(config.use_firestore_audit)
        assert_equals(config.tenant_id_header, "X-BAS-Tenant")
        assert_equals(config.session_timeout, 1800)
        assert_equals(config.max_concurrent_sessions, 3)
        assert_equals(config.max_login_attempts, 5)
        assert_equals(config.lockout_duration, 900)
        assert_equals(config.password_min_length, 12)
        assert_equals(config.password_history_count, 5)
        assert_equals(config.rate_limit_per_ip, 100)
        assert_equals(config.rate_limit_per_user, 50)
        assert_equals(config.auth_attempts_per_15min, 5)

    def test_config_from_env_variables(self):
        """Test configuration loading from environment variables."""
        env_vars = {
            'BAS_AUTH_ENABLED': 'false',
            'BAS_AUTH_MODE': 'shadow',
            'USE_FIRESTORE_TELEMETRY': '1',
            'USE_FIRESTORE_AUTH': '1',
            'USE_FIRESTORE_AUDIT': '0',
            'GOOGLE_CLOUD_PROJECT': 'test-project',
            'FIRESTORE_EMULATOR_HOST': 'localhost:8080',
            'TENANT_ID_HEADER': 'X-Custom-Tenant',
            'BAS_SESSION_TIMEOUT': '3600',
            'BAS_MAX_CONCURRENT_SESSIONS': '5',
            'BAS_MAX_LOGIN_ATTEMPTS': '3',
            'BAS_LOCKOUT_DURATION': '1800'
        }
        
        with patch.dict(os.environ, env_vars):
            config = AuthConfig.from_env()
            
            assert_false(config.auth_enabled)
            assert_equals(config.auth_mode, "shadow")
            assert_true(config.use_firestore_telemetry)
            assert_true(config.use_firestore_auth)
            assert_false(config.use_firestore_audit)
            assert_equals(config.gcp_project_id, "test-project")
            assert_equals(config.firestore_emulator_host, "localhost:8080")
            assert_equals(config.tenant_id_header, "X-Custom-Tenant")
            assert_equals(config.session_timeout, 3600)
            assert_equals(config.max_concurrent_sessions, 5)
            assert_equals(config.max_login_attempts, 3)
            assert_equals(config.lockout_duration, 1800)

    def test_config_from_env_defaults(self):
        """Test configuration loading with default values when env vars are missing."""
        with patch.dict(os.environ, {}, clear=True):
            config = AuthConfig.from_env()
            
            # Should use default values
            assert_true(config.auth_enabled)
            assert_equals(config.auth_mode, "user_password")
            assert_false(config.use_firestore_telemetry)
            assert_false(config.use_firestore_auth)
            assert_false(config.use_firestore_audit)
            assert_equals(config.tenant_id_header, "X-BAS-Tenant")
            assert_equals(config.session_timeout, 1800)
            assert_equals(config.max_concurrent_sessions, 3)
            assert_equals(config.max_login_attempts, 5)
            assert_equals(config.lockout_duration, 900)

    def test_config_from_file_success(self):
        """Test configuration loading from JSON file."""
        config_data = {
            "auth_enabled": False,
            "auth_mode": "enforced",
            "use_firestore_telemetry": True,
            "use_firestore_auth": True,
            "use_firestore_audit": True,
            "gcp_project_id": "test-project",
            "firestore_emulator_host": "localhost:8080",
            "tenant_id_header": "X-Custom-Tenant",
            "session_timeout": 7200,
            "max_concurrent_sessions": 10,
            "max_login_attempts": 3,
            "lockout_duration": 1800,
            "password_min_length": 16,
            "password_history_count": 10,
            "rate_limit_per_ip": 200,
            "rate_limit_per_user": 100,
            "auth_attempts_per_15min": 10
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = AuthConfig.from_file(temp_path)
            
            assert_false(config.auth_enabled)
            assert_equals(config.auth_mode, "enforced")
            assert_true(config.use_firestore_telemetry)
            assert_true(config.use_firestore_auth)
            assert_true(config.use_firestore_audit)
            assert_equals(config.gcp_project_id, "test-project")
            assert_equals(config.firestore_emulator_host, "localhost:8080")
            assert_equals(config.tenant_id_header, "X-Custom-Tenant")
            assert_equals(config.session_timeout, 7200)
            assert_equals(config.max_concurrent_sessions, 10)
            assert_equals(config.max_login_attempts, 3)
            assert_equals(config.lockout_duration, 1800)
            assert_equals(config.password_min_length, 16)
            assert_equals(config.password_history_count, 10)
            assert_equals(config.rate_limit_per_ip, 200)
            assert_equals(config.rate_limit_per_user, 100)
            assert_equals(config.auth_attempts_per_15min, 10)
        finally:
            os.unlink(temp_path)

    def test_config_from_file_not_found(self):
        """Test configuration loading from non-existent file."""
        config = AuthConfig.from_file("nonexistent_config.json")
        
        # Should return default configuration
        assert_true(config.auth_enabled)
        assert_equals(config.auth_mode, "user_password")

    def test_config_from_file_invalid_json(self):
        """Test configuration loading from invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name
        
        try:
            config = AuthConfig.from_file(temp_path)
            
            # Should return default configuration on error
            assert_true(config.auth_enabled)
            assert_equals(config.auth_mode, "user_password")
        finally:
            os.unlink(temp_path)

    def test_config_validation_disabled_auth(self):
        """Test configuration validation when auth is disabled."""
        config = AuthConfig(auth_enabled=False)
        
        result = config.validate()
        assert_true(result)

    def test_config_validation_disabled_mode(self):
        """Test configuration validation when auth mode is disabled."""
        config = AuthConfig(auth_mode="disabled")
        
        result = config.validate()
        assert_true(result)

    def test_config_validation_enabled_auth_valid(self):
        """Test configuration validation with valid enabled auth settings."""
        config = AuthConfig(
            auth_enabled=True,
            auth_mode="user_password",
            session_timeout=1800,
            max_concurrent_sessions=3,
            password_min_length=12
        )
        
        result = config.validate()
        assert_true(result)

    def test_config_validation_session_timeout_too_short(self):
        """Test configuration validation with session timeout too short."""
        config = AuthConfig(
            auth_enabled=True,
            session_timeout=100  # Too short (less than 5 minutes)
        )
        
        with patch('auth.config.logger') as mock_logger:
            result = config.validate()
            assert_true(result)  # Should still pass but log warning
            mock_logger.warning.assert_called()

    def test_config_validation_max_concurrent_sessions_too_low(self):
        """Test configuration validation with max concurrent sessions too low."""
        config = AuthConfig(
            auth_enabled=True,
            max_concurrent_sessions=0
        )
        
        with patch('auth.config.logger') as mock_logger:
            result = config.validate()
            assert_true(result)  # Should still pass but log warning
            mock_logger.warning.assert_called()

    def test_config_validation_password_min_length_too_low(self):
        """Test configuration validation with password minimum length too low."""
        config = AuthConfig(
            auth_enabled=True,
            password_min_length=6  # Too low (less than 8)
        )
        
        with patch('auth.config.logger') as mock_logger:
            result = config.validate()
            assert_true(result)  # Should still pass but log warning
            mock_logger.warning.assert_called()

    def test_config_firestore_settings_combinations(self):
        """Test various Firestore settings combinations."""
        # Test all Firestore features enabled
        config1 = AuthConfig(
            use_firestore_telemetry=True,
            use_firestore_auth=True,
            use_firestore_audit=True,
            gcp_project_id="test-project"
        )
        assert_true(config1.use_firestore_telemetry)
        assert_true(config1.use_firestore_auth)
        assert_true(config1.use_firestore_audit)
        
        # Test partial Firestore features enabled
        config2 = AuthConfig(
            use_firestore_telemetry=True,
            use_firestore_auth=False,
            use_firestore_audit=True,
            gcp_project_id="test-project"
        )
        assert_true(config2.use_firestore_telemetry)
        assert_false(config2.use_firestore_auth)
        assert_true(config2.use_firestore_audit)
        
        # Test no Firestore features enabled
        config3 = AuthConfig(
            use_firestore_telemetry=False,
            use_firestore_auth=False,
            use_firestore_audit=False
        )
        assert_false(config3.use_firestore_telemetry)
        assert_false(config3.use_firestore_auth)
        assert_false(config3.use_firestore_audit)

    def test_config_emulator_settings(self):
        """Test Firestore emulator settings."""
        config = AuthConfig(
            firestore_emulator_host="localhost:8080",
            gcp_project_id="test-project"
        )
        
        assert_equals(config.firestore_emulator_host, "localhost:8080")
        assert_equals(config.gcp_project_id, "test-project")

    def test_config_tenant_header_customization(self):
        """Test custom tenant header configuration."""
        config = AuthConfig(tenant_id_header="X-Custom-Tenant-ID")
        assert_equals(config.tenant_id_header, "X-Custom-Tenant-ID")

    def test_config_security_settings_validation(self):
        """Test security settings validation."""
        config = AuthConfig(
            max_login_attempts=10,
            lockout_duration=1800,
            password_min_length=16,
            password_history_count=10,
            rate_limit_per_ip=200,
            rate_limit_per_user=100,
            auth_attempts_per_15min=15
        )
        
        assert_equals(config.max_login_attempts, 10)
        assert_equals(config.lockout_duration, 1800)
        assert_equals(config.password_min_length, 16)
        assert_equals(config.password_history_count, 10)
        assert_equals(config.rate_limit_per_ip, 200)
        assert_equals(config.rate_limit_per_user, 100)
        assert_equals(config.auth_attempts_per_15min, 15)

    def test_config_session_settings_validation(self):
        """Test session settings validation."""
        config = AuthConfig(
            session_timeout=3600,
            max_concurrent_sessions=5,
            session_rotation=True
        )
        
        assert_equals(config.session_timeout, 3600)
        assert_equals(config.max_concurrent_sessions, 5)
        assert_true(config.session_rotation)

    def test_config_immutability(self):
        """Test that configuration objects are properly structured."""
        config = AuthConfig()
        
        # Test that we can access all attributes
        assert_is_not_none(config.auth_enabled)
        assert_is_not_none(config.auth_mode)
        assert_is_not_none(config.use_firestore_telemetry)
        assert_is_not_none(config.use_firestore_auth)
        assert_is_not_none(config.use_firestore_audit)
        assert_is_not_none(config.session_timeout)
        assert_is_not_none(config.max_concurrent_sessions)
        assert_is_not_none(config.max_login_attempts)
        assert_is_not_none(config.lockout_duration)
        assert_is_not_none(config.password_min_length)
        assert_is_not_none(config.password_history_count)
        assert_is_not_none(config.rate_limit_per_ip)
        assert_is_not_none(config.rate_limit_per_user)
        assert_is_not_none(config.auth_attempts_per_15min)

    def test_config_edge_case_values(self):
        """Test configuration with edge case values."""
        config = AuthConfig(
            session_timeout=1,  # Very short
            max_concurrent_sessions=1,  # Minimum
            password_min_length=8,  # Minimum recommended
            max_login_attempts=1,  # Very restrictive
            lockout_duration=1  # Very short lockout
        )
        
        assert_equals(config.session_timeout, 1)
        assert_equals(config.max_concurrent_sessions, 1)
        assert_equals(config.password_min_length, 8)
        assert_equals(config.max_login_attempts, 1)
        assert_equals(config.lockout_duration, 1)

    def test_config_large_values(self):
        """Test configuration with large values."""
        config = AuthConfig(
            session_timeout=86400,  # 24 hours
            max_concurrent_sessions=100,
            password_min_length=64,
            max_login_attempts=100,
            lockout_duration=86400,  # 24 hours
            rate_limit_per_ip=10000,
            rate_limit_per_user=5000,
            auth_attempts_per_15min=1000
        )
        
        assert_equals(config.session_timeout, 86400)
        assert_equals(config.max_concurrent_sessions, 100)
        assert_equals(config.password_min_length, 64)
        assert_equals(config.max_login_attempts, 100)
        assert_equals(config.lockout_duration, 86400)
        assert_equals(config.rate_limit_per_ip, 10000)
        assert_equals(config.rate_limit_per_user, 5000)
        assert_equals(config.auth_attempts_per_15min, 1000)

    def test_config_boolean_feature_flags(self):
        """Test boolean feature flag combinations."""
        # Test all combinations of boolean flags
        combinations = [
            (True, True, True),
            (True, True, False),
            (True, False, True),
            (True, False, False),
            (False, True, True),
            (False, True, False),
            (False, False, True),
            (False, False, False)
        ]
        
        for telemetry, auth, audit in combinations:
            config = AuthConfig(
                use_firestore_telemetry=telemetry,
                use_firestore_auth=auth,
                use_firestore_audit=audit
            )
            
            assert_equals(config.use_firestore_telemetry, telemetry)
            assert_equals(config.use_firestore_auth, auth)
            assert_equals(config.use_firestore_audit, audit)

    def test_config_environment_variable_type_conversion(self):
        """Test environment variable type conversion."""
        env_vars = {
            'BAS_SESSION_TIMEOUT': '7200',
            'BAS_MAX_CONCURRENT_SESSIONS': '10',
            'BAS_MAX_LOGIN_ATTEMPTS': '3',
            'BAS_LOCKOUT_DURATION': '1800'
        }
        
        with patch.dict(os.environ, env_vars):
            config = AuthConfig.from_env()
            
            # Verify type conversion
            assert_equals(type(config.session_timeout), int)
            assert_equals(type(config.max_concurrent_sessions), int)
            assert_equals(type(config.max_login_attempts), int)
            assert_equals(type(config.lockout_duration), int)
            
            assert_equals(config.session_timeout, 7200)
            assert_equals(config.max_concurrent_sessions, 10)
            assert_equals(config.max_login_attempts, 3)
            assert_equals(config.lockout_duration, 1800)
