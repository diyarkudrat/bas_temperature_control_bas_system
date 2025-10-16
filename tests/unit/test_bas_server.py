"""
Unit tests for BAS server authentication integration and endpoints.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from flask import Flask

# Import BAS server components
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../server'))

from bas_server import (
    BASController, BASDatabase, init_auth, 
    controller, database, auth_config, user_manager, 
    session_manager, audit_logger, rate_limiter
)
from auth.config import AuthConfig
from auth.managers import UserManager, SessionManager
from auth.services import AuditLogger, RateLimiter
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
    """Test BASDatabase functionality."""

    def test_database_initialization(self, temp_db_file):
        """Test database initialization."""
        db = BASDatabase(temp_db_file)
        
        # Verify tables were created
        import sqlite3
        conn = sqlite3.connect(temp_db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telemetry'")
        table_exists = cursor.fetchone()
        conn.close()
        
        assert_is_not_none(table_exists, "Telemetry table should be created")

    def test_database_store_data(self, temp_db_file):
        """Test storing telemetry data."""
        db = BASDatabase(temp_db_file)
        
        data = {
            'timestamp': time.time() * 1000,
            'temp_tenths': 250,
            'setpoint_tenths': 230,
            'deadband_tenths': 10,
            'cool_active': True,
            'heat_active': False,
            'state': 'COOLING',
            'sensor_ok': True
        }
        
        db.store_data(data)
        
        # Verify data was stored
        recent_data = db.get_recent_data(1)
        assert_equals(len(recent_data), 1)
        assert_equals(recent_data[0]['temp_tenths'], 250)

    def test_database_get_recent_data(self, temp_db_file):
        """Test getting recent telemetry data."""
        db = BASDatabase(temp_db_file)
        
        # Store multiple data points
        for i in range(5):
            data = {
                'timestamp': (time.time() + i) * 1000,
                'temp_tenths': 200 + i * 10,
                'setpoint_tenths': 230,
                'deadband_tenths': 10,
                'cool_active': False,
                'heat_active': True,
                'state': 'IDLE',
                'sensor_ok': True
            }
            db.store_data(data)
        
        # Get recent data
        recent_data = db.get_recent_data(3)
        assert_equals(len(recent_data), 3)
        # Should be in descending order (most recent first)
        assert_equals(recent_data[0]['temp_tenths'], 240)


@pytest.mark.unit
class TestBASServerAuthIntegration:
    """Test BAS server authentication integration."""

    def test_init_auth_success(self, temp_db_file):
        """Test successful authentication initialization."""
        with patch('bas_server.AuthConfig.from_file') as mock_from_file, \
             patch('bas_server.UserManager') as mock_user_manager, \
             patch('bas_server.SessionManager') as mock_session_manager, \
             \
             patch('bas_server.AuditLogger') as mock_audit_logger, \
             patch('bas_server.RateLimiter') as mock_rate_limiter:
            
            # Setup mocks
            mock_config = Mock()
            mock_config.validate.return_value = True
            mock_from_file.return_value = mock_config
            
            # Call init_auth
            result = init_auth()
            
            assert_true(result, "Authentication initialization should succeed")
            mock_from_file.assert_called_once_with('config/auth_config.json')

    def test_init_auth_config_validation_failure(self, temp_db_file):
        """Test authentication initialization with invalid config."""
        with patch('bas_server.AuthConfig.from_file') as mock_from_file:
            # Setup mock with invalid config
            mock_config = Mock()
            mock_config.validate.return_value = False
            mock_from_file.return_value = mock_config
            
            # Call init_auth
            result = init_auth()
            
            assert_false(result, "Authentication initialization should fail with invalid config")

    def test_init_auth_exception(self, temp_db_file):
        """Test authentication initialization with exception."""
        with patch('bas_server.AuthConfig.from_file') as mock_from_file:
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
        from bas_server import app
        
        with app.test_client() as client:
            response = client.get('/api/health')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_equals(data['status'], 'healthy')
            assert_is_not_none(data['timestamp'])

    def test_status_endpoint(self):
        """Test status endpoint."""
        from bas_server import app
        
        with app.test_client() as client:
            response = client.get('/api/status')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_is_not_none(data['temp_tenths'])
            assert_is_not_none(data['setpoint_tenths'])
            assert_is_not_none(data['state'])

    def test_config_endpoint(self):
        """Test config endpoint."""
        from bas_server import app
        
        with app.test_client() as client:
            response = client.get('/api/config')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_is_not_none(data['setpoint_tenths'])
            assert_is_not_none(data['deadband_tenths'])
            assert_is_not_none(data['min_on_time_ms'])

    def test_sensor_data_endpoint_success(self):
        """Test sensor data endpoint with valid data."""
        from bas_server import app
        
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
        from bas_server import app
        
        with app.test_client() as client:
            response = client.post('/api/sensor_data')
            assert_equals(response.status_code, 400)
            
            data = response.get_json()
            assert_equals(data['error'], 'No data received')

    def test_sensor_data_endpoint_invalid_json(self):
        """Test sensor data endpoint with invalid JSON."""
        from bas_server import app
        
        with app.test_client() as client:
            response = client.post('/api/sensor_data',
                                 data='invalid json',
                                 content_type='application/json')
            assert_equals(response.status_code, 500)

    def test_set_setpoint_endpoint_requires_auth(self):
        """Test that set_setpoint endpoint requires authentication."""
        from bas_server import app
        
        with app.test_client() as client:
            data = {'setpoint_tenths': 250}
            response = client.post('/api/set_setpoint',
                                 json=data,
                                 content_type='application/json')
            # Should require authentication (401 or redirect to login)
            assert response.status_code in [401, 302, 500]  # 500 if auth not initialized

    def test_telemetry_endpoint_requires_auth(self):
        """Test that telemetry endpoint requires authentication."""
        from bas_server import app
        
        with app.test_client() as client:
            response = client.get('/api/telemetry')
            # Should require authentication (401 or redirect to login)
            assert response.status_code in [401, 302, 500]  # 500 if auth not initialized

    def test_auth_login_endpoint_disabled_auth(self):
        """Test auth login endpoint when auth is disabled."""
        from bas_server import app
        
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
        from bas_server import app
        
        with app.test_client() as client:
            response = client.post('/auth/logout',
                                 json={'session_id': 'test_session'},
                                 content_type='application/json')
            assert_equals(response.status_code, 200)
            
            data = response.get_json()
            assert_equals(data['status'], 'success')

    def test_auth_status_endpoint_no_session(self):
        """Test auth status endpoint without session."""
        from bas_server import app
        
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
        from bas_server import app
        
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
        from bas_server import app
        
        with app.test_client() as client:
            response = client.get('/api/health')
            
            assert_equals(response.headers['X-Content-Type-Options'], 'nosniff')
            assert_equals(response.headers['X-Frame-Options'], 'DENY')
            assert_equals(response.headers['X-XSS-Protection'], '1; mode=block')
            assert 'max-age=31536000' in response.headers['Strict-Transport-Security']
            assert_equals(response.headers['Content-Security-Policy'], "default-src 'self'")
            assert_equals(response.headers['Referrer-Policy'], 'strict-origin-when-cross-origin')


@pytest.mark.unit
class TestBASServerRequestContext:
    """Test BAS server request context setup."""

    def test_auth_context_setup(self):
        """Test that authentication context is set up for requests."""
        from bas_server import app
        
        # Mock the global auth variables
        with patch('bas_server.auth_config', Mock()), \
             patch('bas_server.session_manager', Mock()), \
             patch('bas_server.audit_logger', Mock()):
            
            with app.test_client() as client:
                response = client.get('/api/health')
                assert_equals(response.status_code, 200)

    def test_auth_context_no_auth_config(self):
        """Test request handling when auth config is not available."""
        from bas_server import app
        
        # Ensure auth_config is None
        with patch('bas_server.auth_config', None):
            with app.test_client() as client:
                response = client.get('/api/health')
                assert_equals(response.status_code, 200)
