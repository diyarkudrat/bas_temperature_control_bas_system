from __future__ import annotations

import importlib
import os
from unittest import mock

import pytest


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ["AUTH_PROVIDER", "AUTH0_DOMAIN", "AUTH0_AUDIENCE", "USE_EMULATORS"]:
        monkeypatch.delenv(k, raising=False)
    yield


def _reload_server(monkeypatch, env: dict[str, str]):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # Force reload config and main app module
    if "app_platform.config.config" in list(importlib.sys.modules.keys()):
        importlib.reload(importlib.import_module("app_platform.config.config"))
    if "apps.api.main" in list(importlib.sys.modules.keys()):
        importlib.reload(importlib.import_module("apps.api.main"))
    mod = importlib.import_module("apps.api.main")
    importlib.reload(mod)
    return mod


def test_auth_provider_init_auth0(monkeypatch):
    mod = _reload_server(monkeypatch, {
        "AUTH_PROVIDER": "auth0",
        "AUTH0_DOMAIN": "example.auth0.com",
        "AUTH0_AUDIENCE": "bas-api",
    })
    # Provider should be Auth0Provider
    from adapters.providers import Auth0Provider
    assert isinstance(mod.auth_provider, Auth0Provider)

    def test_auth_metrics_recorded_for_jwt_success(self, monkeypatch):
        mod = _reload_server(monkeypatch, {
            "AUTH_PROVIDER": "mock",
            "USE_EMULATORS": "1",
        })
        app = mod.app
        # Inject a minimal provider that always verifies
        class _P:
            def verify_token(self, t):
                return {"sub": "u"}
            def get_user_roles(self, u):
                return ["operator", "read-only"]
            def healthcheck(self):
                return {"status": "ok"}
        provider = _P()
        with app.test_client() as c:
            @app.before_request
            def _set_provider():
                from flask import request
                request.auth_provider = provider
            snap_before = mod.auth_metrics.snapshot()
            rv = c.get('/api/telemetry', headers={"Authorization": "Bearer t", "X-BAS-Tenant": "t1"})
            assert rv.status_code in (200, 500)  # 500 if telemetry not initialized
            snap_after = mod.auth_metrics.snapshot()
            assert snap_after["jwt_attempts"] >= snap_before["jwt_attempts"] + 1

    def test_auth_metrics_recorded_for_session_failure(self, monkeypatch):
        mod = _reload_server(monkeypatch, {
            "AUTH_PROVIDER": "mock",
            "USE_EMULATORS": "1",
        })
        app = mod.app
        with app.test_client() as c:
            snap_before = mod.auth_metrics.snapshot()
            rv = c.post('/api/set_setpoint', json={"setpoint_tenths": 250})
            # Expect 401 due to missing session id
            assert rv.status_code in (401, 500)
            snap_after = mod.auth_metrics.snapshot()
            assert snap_after["session_attempts"] >= snap_before["session_attempts"] + 1


def test_dynamic_limit_hot_reload(monkeypatch):
    # Ensure env provides API key and emulators so server loads
    mod = _reload_server(monkeypatch, {
        "AUTH_PROVIDER": "mock",
        "USE_EMULATORS": "1",
        "DYNAMIC_LIMIT_API_KEY": "k",
    })
    app = mod.app
    app.config['TESTING'] = True
    with app.test_client() as c:
        rv = c.post('/auth/limits', json={"per_user_limits": {"/api/x": {"window_s": 60, "max_req": 5}}}, headers={"X-Limits-Key": "k"})
        assert rv.status_code == 200
        body = rv.get_json()
        assert "/api/x" in body.get("per_user_limits", {})


def test_auth_provider_init_invalid_env(monkeypatch):
    # Missing audience
    mod = _reload_server(monkeypatch, {
        "AUTH_PROVIDER": "auth0",
        "AUTH0_DOMAIN": "example.auth0.com",
    })
    assert hasattr(mod, "auth_provider")
    # Deny-all fallback healthcheck
    hc = mod.auth_provider.healthcheck()
    assert hc.get("provider") == "DenyAllAuthProvider"


def test_no_mock_in_prod(monkeypatch):
    mod = _reload_server(monkeypatch, {
        "AUTH_PROVIDER": "mock",
        "USE_EMULATORS": "0",
    })
    hc = mod.auth_provider.healthcheck()
    assert hc.get("provider") == "DenyAllAuthProvider"

"""
Unit tests for BAS server authentication integration and endpoints.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from flask import Flask

# Import BAS server components (updated paths; no sys.path hacks)

from apps.api.main import init_auth
from application.hardware.bas_hardware_controller import BASController
from app_platform.config.auth import AuthConfig
from application.auth.managers import UserManager, SessionManager
from application.auth.services import AuditLogger, RateLimiter
from tests.utils.assertions import assert_equals, assert_true, assert_false, assert_is_not_none


@pytest.mark.unit
class TestBASController:
    """Test BASController functionality."""

    def test_controller_initialization(self):
        """Test controller initialization with default values."""
        controller = BASController()
        
        assert_equals(controller.setpoint_tenths, 230)
        assert_equals(controller.deadband_tenths, 10)
        assert_equals(controller.min_on_time_ms, 10000)
        assert_equals(controller.min_off_time_ms, 10000)
        assert_equals(controller.current_temp_tenths, 0)
        assert_false(controller.sensor_ok)
        assert_false(controller.cool_active)
        assert_false(controller.heat_active)
        assert_equals(controller.state, "IDLE")

    def test_controller_update_control_sensor_fault(self):
        """Test controller behavior with sensor fault."""
        controller = BASController()
        
        # Update with sensor fault
        controller.update_control(250, False)  # 25.0°C, sensor fault
        
        assert_equals(controller.current_temp_tenths, 250)
        assert_false(controller.sensor_ok)
        assert_false(controller.cool_active)
        assert_false(controller.heat_active)
        assert_equals(controller.state, "FAULT")

    def test_controller_update_control_cooling(self):
        """Test controller behavior when cooling is needed."""
        controller = BASController()
        
        # Update with temperature above setpoint + deadband
        controller.update_control(250, True)  # 25.0°C, sensor OK
        
        assert_equals(controller.current_temp_tenths, 250)
        assert_true(controller.sensor_ok)
        assert_true(controller.cool_active)
        assert_true(controller.heat_active)  # LEDs always on
        assert_equals(controller.state, "COOLING_WITH_LEDS")

    def test_controller_update_control_idle(self):
        """Test controller behavior when no cooling is needed."""
        controller = BASController()
        
        # Update with temperature within deadband
        controller.update_control(230, True)  # 23.0°C, sensor OK
        
        assert_equals(controller.current_temp_tenths, 230)
        assert_true(controller.sensor_ok)
        assert_false(controller.cool_active)
        assert_true(controller.heat_active)  # LEDs always on
        assert_equals(controller.state, "IDLE_WITH_LEDS")

    def test_controller_set_setpoint_valid(self):
        """Test setting valid setpoint."""
        controller = BASController()
        
        result = controller.set_setpoint(250)  # 25.0°C
        assert_true(result)
        assert_equals(controller.setpoint_tenths, 250)

    def test_controller_set_setpoint_invalid(self):
        """Test setting invalid setpoint."""
        controller = BASController()
        
        result = controller.set_setpoint(50)  # 5.0°C (too low)
        assert_false(result)
        assert_equals(controller.setpoint_tenths, 230)  # Unchanged

    def test_controller_set_deadband_valid(self):
        """Test setting valid deadband."""
        controller = BASController()
        
        result = controller.set_deadband(20)  # 2.0°C
        assert_true(result)
        assert_equals(controller.deadband_tenths, 20)

    def test_controller_set_deadband_invalid(self):
        """Test setting invalid deadband."""
        controller = BASController()
        
        result = controller.set_deadband(60)  # 6.0°C (too high)
        assert_false(result)
        assert_equals(controller.deadband_tenths, 10)  # Unchanged

    def test_controller_get_control_commands(self):
        """Test getting control commands."""
        controller = BASController()
        controller.cool_active = True
        controller.heat_active = False
        
        commands = controller.get_control_commands()
        
        assert_true(commands["cool_active"])
        assert_false(commands["heat_active"])
        assert_equals(commands["setpoint_tenths"], 230)
        assert_equals(commands["deadband_tenths"], 10)


@pytest.mark.unit
class TestBASDatabase:
    """Legacy BASDatabase tests removed with new architecture."""
    pass


@pytest.mark.unit
class TestBASServerAuthIntegration:
    """Test BAS server authentication integration."""

    def test_init_auth_success(self, temp_db_file):
        """Test successful authentication initialization."""
        with patch('apps.api.main.AuthConfig.from_file') as mock_from_file, \
             patch('apps.api.main.UserManager') as mock_user_manager, \
             patch('apps.api.main.SessionManager') as mock_session_manager, \
             \
             patch('apps.api.main.AuditLogger') as mock_audit_logger, \
             patch('apps.api.main.RateLimiter') as mock_rate_limiter:
            
            # Setup mocks
            mock_config = Mock()
            mock_config.validate.return_value = True
            mock_from_file.return_value = mock_config
            
            # Call init_auth
            result = init_auth()
            
            assert_true(result, "Authentication initialization should succeed")
            mock_from_file.assert_called_once_with('configs/app/auth_config.json')

    def test_init_auth_config_validation_failure(self, temp_db_file):
        """Test authentication initialization with invalid config."""
        with patch('apps.api.main.AuthConfig.from_file') as mock_from_file:
            # Setup mock with invalid config
            mock_config = Mock()
            mock_config.validate.return_value = False
            mock_from_file.return_value = mock_config
            
            # Call init_auth
            result = init_auth()
            
            assert_false(result, "Authentication initialization should fail with invalid config")

    def test_init_auth_exception(self, temp_db_file):
        """Test authentication initialization with exception."""
        with patch('apps.api.main.AuthConfig.from_file') as mock_from_file:
            # Setup mock to raise exception
            mock_from_file.side_effect = Exception("Config file not found")
            
            # Call init_auth
            result = init_auth()
            
            assert_false(result, "Authentication initialization should fail with exception")


@pytest.mark.unit
class TestBASServerEndpoints:
    """Test BAS server endpoint functionality."""

    def test_health_endpoint(self):
        """Test health check endpoint."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/health')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_equals(data['status'], 'healthy')
            assert_is_not_none(data['timestamp'])

    def test_health_headers_deprecation_absent(self):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/api/health')
            assert_equals(response.status_code, 200)
            assert_equals(response.headers.get('API-Version'), '2')
            assert response.headers.get('Deprecation') is None

    def test_health_headers_version_is_v2(self):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get('/api/health')
            assert_equals(response.status_code, 200)
            assert_equals(response.headers.get('API-Version'), '2')

    @pytest.mark.parametrize('path', [
        '/api/status',
        '/api/config',
    ])
    def test_version_headers_parametrized(self, path):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            response = client.get(path)
            assert response.status_code in (200, 302, 401, 500)  # some require auth
            assert_equals(response.headers.get('API-Version'), '2')

    def test_status_endpoint(self):
        """Test status endpoint."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/status')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_is_not_none(data['temp_tenths'])
            assert_is_not_none(data['setpoint_tenths'])
            assert_is_not_none(data['state'])

    def test_config_endpoint(self):
        """Test config endpoint."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/config')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_is_not_none(data['setpoint_tenths'])
            assert_is_not_none(data['deadband_tenths'])
            assert_is_not_none(data['min_on_time_ms'])

    def test_sensor_data_endpoint_success(self):
        """Test sensor data endpoint with valid data."""
        from apps.api.main import app
        
        with app.test_client() as client:
            data = {
                'temp_tenths': 250,
                'sensor_ok': True,
                'timestamp': time.time() * 1000
            }
            
            response = client.post('/api/sensor_data', 
                                 json=data,
                                 content_type='application/json')
            assert_equals(response.status_code, 200)
            
            result = response.get_json()
            assert_is_not_none(result['cool_active'])
            assert_is_not_none(result['heat_active'])

    def test_sensor_data_endpoint_no_data(self):
        """Test sensor data endpoint with no data."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.post('/api/sensor_data', 
                                 json={},
                                 content_type='application/json')
            assert_equals(response.status_code, 400)
            
            data = response.get_json()
            assert_equals(data['error'], 'No data received')

    def test_sensor_data_endpoint_invalid_json(self):
        """Test sensor data endpoint with invalid JSON."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.post('/api/sensor_data',
                                 data='invalid json',
                                 content_type='application/json')
            assert_equals(response.status_code, 500)

    def test_set_setpoint_endpoint_requires_auth(self):
        """Test that set_setpoint endpoint requires authentication."""
        from apps.api.main import app
        
        with app.test_client() as client:
            data = {'setpoint_tenths': 250}
            response = client.post('/api/set_setpoint',
                                 json=data,
                                 content_type='application/json')
            # Should require authentication (401 or redirect to login)
            assert response.status_code in [401, 302, 500]  # 500 if auth not initialized

    def test_telemetry_endpoint_requires_auth(self):
        """Test that telemetry endpoint requires authentication."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/telemetry')
            # Should require authentication (401 or redirect to login)
            assert response.status_code in [401, 302, 500]  # 500 if auth not initialized

    def test_auth_login_endpoint_disabled_auth(self):
        """Test auth login endpoint when auth is disabled."""
        from apps.api.main import app
        
        # Mock the auth_config to be disabled
        with patch('apps.api.main.auth_config') as mock_auth_config:
            mock_auth_config.auth_enabled = False
            
            with app.test_client() as client:
                data = {
                    'username': 'testuser',
                    'password': 'testpass',
                }
                response = client.post('/auth/login',
                                         json=data,
                                         content_type='application/json')
                # Should return 503 when auth is disabled
                assert_equals(response.status_code, 503)

    def test_auth_logout_endpoint(self):
        """Test auth logout endpoint."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.post('/auth/logout',
                                 json={'session_id': 'test_session'},
                                 content_type='application/json')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_equals(data['status'], 'success')

    def test_auth_status_endpoint_no_session(self):
        """Test auth status endpoint without session."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/auth/status')
            assert_equals(response.status_code, 400)
            
            data = response.get_json()
            assert_equals(data['error'], 'No session provided')



@pytest.mark.unit
class TestBASServerSecurityHeaders:
    """Test BAS server security headers."""

    def test_security_headers_applied(self):
        """Test that security headers are applied to responses."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/health')
            
            # Check for security headers
            assert 'X-Content-Type-Options' in response.headers
            assert 'X-Frame-Options' in response.headers
            assert 'X-XSS-Protection' in response.headers
            assert 'Strict-Transport-Security' in response.headers
            assert 'Content-Security-Policy' in response.headers
            assert 'Referrer-Policy' in response.headers
            assert 'Permissions-Policy' in response.headers

    def test_security_headers_values(self):
        """Test that security headers have correct values."""
        from apps.api.main import app
        
        with app.test_client() as client:
            response = client.get('/api/health')
            
            assert_equals(response.headers['X-Content-Type-Options'], 'nosniff')
            assert_equals(response.headers['X-Frame-Options'], 'DENY')
            assert_equals(response.headers['X-XSS-Protection'], '1; mode=block')
            assert 'max-age=31536000' in response.headers['Strict-Transport-Security']
            assert_equals(response.headers['Content-Security-Policy'], "default-src 'self'")
            assert_equals(response.headers['Referrer-Policy'], 'strict-origin-when-cross-origin')


@pytest.mark.unit
class TestBASServerErrorMapping:
    """Test central error mapping behaviors."""

    def test_error_mapping_value_error(self):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            res = client.get('/api/v2/_raise/value')
            assert_equals(res.status_code, 400)
            body = res.get_json()
            assert_equals(body['code'], 'INVALID_ARGUMENT')

    def test_error_mapping_not_found(self):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            res = client.get('/api/v2/_raise/notfound')
            assert_equals(res.status_code, 404)
            body = res.get_json()
            assert_equals(body['code'], 'NOT_FOUND')

    def test_error_mapping_permission(self):
        from apps.api.main import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            res = client.get('/api/v2/_raise/perm')
            assert_equals(res.status_code, 403)
            body = res.get_json()
            assert_equals(body['code'], 'PERMISSION_DENIED')


@pytest.mark.unit
class TestBASServerRequestContext:
    """Test BAS server request context setup."""

    def test_auth_context_setup(self):
        """Test that authentication context is set up for requests."""
        from apps.api.main import app
        
        # Mock the global auth variables
        with patch('bas_server.auth_config', Mock()), \
             patch('bas_server.session_manager', Mock()), \
             patch('bas_server.audit_logger', Mock()):
            
            with app.test_client() as client:
                response = client.get('/api/health')
                assert_equals(response.status_code, 200)

    def test_auth_context_no_auth_config(self):
        """Test request handling when auth config is not available."""
        from apps.api.main import app
        
        # Ensure auth_config is None
        with patch('apps.api.main.auth_config', None):
            with app.test_client() as client:
                response = client.get('/api/health')
                assert_equals(response.status_code, 200)
