"""Tests for Tenant Middleware."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, g, request, jsonify

from server.auth.tenant_middleware import (
    TenantMiddleware, setup_tenant_middleware,
    require_tenant, enforce_tenant_isolation, require_device_access
)
from server.auth.config import AuthConfig
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestTenantMiddleware:
    """Test cases for TenantMiddleware."""
    
    @pytest.fixture
    def auth_config(self):
        """Create auth config for testing."""
        config = Mock(spec=AuthConfig)
        config.tenant_id_header = "X-BAS-Tenant"
        return config
    
    @pytest.fixture
    def audit_service(self):
        """Create mock audit service."""
        service = Mock()
        service.log_tenant_violation = Mock()
        service.log_permission_denied = Mock()
        return service
    
    @pytest.fixture
    def tenant_middleware(self, auth_config, audit_service):
        """Create TenantMiddleware instance."""
        return TenantMiddleware(auth_config, audit_service)
    
    @pytest.fixture
    def mock_request(self):
        """Create mock Flask request."""
        request = Mock()
        request.headers = {}
        request.remote_addr = "192.168.1.100"
        request.endpoint = "test_endpoint"
        request.session = None
        return request
    
    def test_init(self, auth_config, audit_service):
        """Test TenantMiddleware initialization."""
        middleware = TenantMiddleware(auth_config, audit_service)
        
        assert_equals(middleware.auth_config, auth_config, "Should store auth config")
        assert_equals(middleware.audit_service, audit_service, "Should store audit service")
        assert_equals(middleware.tenant_header, "X-BAS-Tenant", "Should store tenant header")
    
    def test_init_no_audit_service(self, auth_config):
        """Test TenantMiddleware initialization without audit service."""
        middleware = TenantMiddleware(auth_config)
        
        assert_equals(middleware.auth_config, auth_config, "Should store auth config")
        assert_is_none(middleware.audit_service, "Should have None audit service")
        assert_equals(middleware.tenant_header, "X-BAS-Tenant", "Should store tenant header")
    
    def test_extract_tenant_id_from_header(self, tenant_middleware, mock_request):
        """Test extracting tenant ID from request header."""
        mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            result = tenant_middleware.extract_tenant_id(mock_request)
            
            assert_equals(result, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should extract tenant ID from header")
    
    def test_extract_tenant_id_from_session(self, tenant_middleware, mock_request):
        """Test extracting tenant ID from session."""
        mock_request.headers = {}  # No header
        mock_request.session = Mock()
        mock_request.session.tenant_id = "tenant_456"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            result = tenant_middleware.extract_tenant_id(mock_request)
            
            assert_equals(result, "tenant_456", "Should extract tenant ID from session")
    
    def test_extract_tenant_id_header_priority(self, tenant_middleware, mock_request):
        """Test that header takes priority over session."""
        mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        mock_request.session = Mock()
        mock_request.session.tenant_id = "tenant_456"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            result = tenant_middleware.extract_tenant_id(mock_request)
            
            assert_equals(result, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should prioritize header over session")
    
    def test_extract_tenant_id_not_found(self, tenant_middleware, mock_request):
        """Test extracting tenant ID when not found."""
        mock_request.headers = {}  # No header
        mock_request.session = None  # No session
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            result = tenant_middleware.extract_tenant_id(mock_request)
            
            assert_is_none(result, "Should return None when tenant ID not found")
    
    def test_extract_tenant_id_session_no_tenant(self, tenant_middleware, mock_request):
        """Test extracting tenant ID from session without tenant_id."""
        mock_request.headers = {}  # No header
        mock_request.session = Mock()
        mock_request.session.tenant_id = None  # No tenant_id in session
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            result = tenant_middleware.extract_tenant_id(mock_request)
            
            assert_is_none(result, "Should return None when session has no tenant_id")
    
    def test_validate_tenant_access_success(self, tenant_middleware):
        """Test successful tenant access validation."""
        result = tenant_middleware.validate_tenant_access("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b")
        
        assert_true(result, "Should allow access to same tenant")
    
    def test_validate_tenant_access_denied(self, tenant_middleware):
        """Test tenant access validation denial."""
        result = tenant_middleware.validate_tenant_access("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "tenant_456")
        
        assert_false(result, "Should deny access to different tenant")
    
    def test_audit_tenant_violation_with_service(self, tenant_middleware):
        """Test auditing tenant violation with audit service."""
        tenant_middleware.audit_tenant_violation(
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            attempted_tenant="tenant_456",
            allowed_tenant="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
        )
        
        tenant_middleware.audit_service.log_tenant_violation.assert_called_once_with(
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            attempted_tenant="tenant_456",
            allowed_tenant="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
        )
    
    def test_audit_tenant_violation_no_service(self, auth_config):
        """Test auditing tenant violation without audit service."""
        middleware = TenantMiddleware(auth_config)  # No audit service
        
        # Should not raise exception
        middleware.audit_tenant_violation(
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            attempted_tenant="tenant_456",
            allowed_tenant="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
        )
    
    def test_audit_tenant_violation_service_exception(self, tenant_middleware):
        """Test auditing tenant violation when service raises exception."""
        tenant_middleware.audit_service.log_tenant_violation.side_effect = Exception("Audit failed")
        
        # Should not raise exception
        tenant_middleware.audit_tenant_violation(
            user_id="user_123",
            username="testuser",
            ip_address="192.168.1.100",
            attempted_tenant="tenant_456",
            allowed_tenant="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
        )
    
    def test_validate_device_ownership_success(self, tenant_middleware):
        """Test successful device ownership validation."""
        devices_service = Mock()
        devices_service.get_device.return_value = {"device_id": "device_123", "tenant_id": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        
        result = tenant_middleware.validate_device_ownership("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "device_123", devices_service)
        
        assert_true(result, "Should return True for valid device ownership")
        devices_service.get_device.assert_called_once_with("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "device_123")
    
    def test_validate_device_ownership_device_not_found(self, tenant_middleware):
        """Test device ownership validation when device not found."""
        devices_service = Mock()
        devices_service.get_device.return_value = None
        
        result = tenant_middleware.validate_device_ownership("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "device_123", devices_service)
        
        assert_false(result, "Should return False when device not found")
    
    def test_validate_device_ownership_no_service(self, tenant_middleware):
        """Test device ownership validation without devices service."""
        result = tenant_middleware.validate_device_ownership("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "device_123", None)
        
        assert_true(result, "Should return True when no service available")
    
    def test_validate_device_ownership_service_exception(self, tenant_middleware):
        """Test device ownership validation when service raises exception."""
        devices_service = Mock()
        devices_service.get_device.side_effect = Exception("Service failed")
        
        result = tenant_middleware.validate_device_ownership("e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "device_123", devices_service)
        
        assert_false(result, "Should return False when service fails")
    
    def test_require_tenant_decorator_success(self, tenant_middleware, mock_request):
        """Test require_tenant decorator with valid tenant ID."""
        mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        
        @tenant_middleware.require_tenant
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                result = test_func()
                
                assert_equals(result, "success", "Should call decorated function")
                assert_equals(mock_g.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id in context")
    
    def test_require_tenant_decorator_missing_tenant(self, tenant_middleware, mock_request):
        """Test require_tenant decorator with missing tenant ID."""
        mock_request.headers = {}  # No tenant header
        mock_request.session = None  # No session
        
        @tenant_middleware.require_tenant
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant ID required"}, 400)
                
                result = test_func()
                
                assert_equals(result, ({"error": "Tenant ID required"}, 400), "Should return error response")
                tenant_middleware.audit_service.log_permission_denied.assert_called_once()
    
    def test_require_tenant_decorator_no_audit_service(self, auth_config, mock_request):
        """Test require_tenant decorator without audit service."""
        middleware = TenantMiddleware(auth_config)  # No audit service
        mock_request.headers = {}  # No tenant header
        mock_request.session = None  # No session
        
        @middleware.require_tenant
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant ID required"}, 400)
                
                result = test_func()
                
                assert_equals(result, ({"error": "Tenant ID required"}, 400), "Should return error response")
    
    def test_enforce_tenant_isolation_decorator_success(self, tenant_middleware, mock_request):
        """Test enforce_tenant_isolation decorator with valid access."""
        mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        mock_request.session = Mock()
        mock_request.session.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
        mock_request.session.username = "testuser"
        mock_request.session.user_id = "user_123"
        
        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                result = test_func()
                
                assert_equals(result, "success", "Should call decorated function")
                assert_equals(mock_g.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id in context")
    
    def test_enforce_tenant_isolation_decorator_missing_tenant(self, tenant_middleware, mock_request):
        """Test enforce_tenant_isolation decorator with missing tenant ID."""
        mock_request.headers = {}  # No tenant header
        mock_request.session = None  # No session
        
        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant ID required"}, 400)
                
                result = test_func()
                
                assert_equals(result, ({"error": "Tenant ID required"}, 400), "Should return error response")
    
    def test_enforce_tenant_isolation_decorator_no_session(self, tenant_middleware, mock_request):
        """Test enforce_tenant_isolation decorator with no user session."""
        mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
        mock_request.session = None  # No session
        
        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                result = test_func()
                
                assert_equals(result, "success", "Should allow access for public endpoints")
                assert_equals(mock_g.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id in context")
    
    def test_enforce_tenant_isolation_decorator_tenant_violation(self, tenant_middleware, mock_request):
        """Test enforce_tenant_isolation decorator with tenant violation."""
        mock_request.headers = {"X-BAS-Tenant": "tenant_456"}  # Different tenant
        mock_request.session = Mock()
        mock_request.session.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"  # User's allowed tenant
        mock_request.session.username = "testuser"
        mock_request.session.user_id = "user_123"
        
        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Access denied to tenant"}, 403)
                
                result = test_func()
                
                assert_equals(result, ({"error": "Access denied to tenant"}, 403), "Should return 403 error")
                tenant_middleware.audit_service.log_tenant_violation.assert_called_once_with(
                    user_id="user_123",
                    username="testuser",
                    ip_address="192.168.1.100",
                    attempted_tenant="tenant_456",
                    allowed_tenant="e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
                )
    
    def test_require_device_access_decorator_success(self, tenant_middleware, mock_request):
        """Test require_device_access decorator with valid device ID."""
        mock_request.is_json = True
        mock_request.json = {"device_id": "device_123"}
        
        @tenant_middleware.require_device_access
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                mock_g.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
                
                result = test_func()
                
                assert_equals(result, "success", "Should call decorated function")
                assert_equals(mock_g.device_id, "device_123", "Should set device_id in context")
    
    def test_setup_tenant_context_outside_app_sets_module_g(self, tenant_middleware, mock_request):
        """setup_tenant_context should set module g when no Flask context."""
        from server.auth import tenant_middleware as tm
        if hasattr(tm.g, 'tenant_id'):
            delattr(tm.g, 'tenant_id')

        mock_request.headers = {"X-BAS-Tenant": "tenant_outside"}
        tenant_id = tenant_middleware.setup_tenant_context(req=mock_request)

        assert_equals(tenant_id, "tenant_outside", "Should return resolved tenant_id")
        assert_equals(getattr(tm.g, 'tenant_id', None), "tenant_outside", "Should set module g.tenant_id")

    def test_setup_tenant_context_inside_app_sets_flask_g(self, tenant_middleware, mock_request):
        """setup_tenant_context should set flask.g when in Flask app context."""
        from flask import Flask, g as flask_g

        app = Flask(__name__)
        mock_request.headers = {"X-BAS-Tenant": "tenant_inside"}
        with app.app_context():
            tenant_id = tenant_middleware.setup_tenant_context(req=mock_request)
            assert_equals(tenant_id, "tenant_inside", "Should return resolved tenant_id")
            assert_equals(getattr(flask_g, 'tenant_id', None), "tenant_inside", "Should set flask.g.tenant_id")

    def test_setup_tenant_context_get_request_exception(self, tenant_middleware):
        """setup_tenant_context should handle get_request exceptions gracefully."""
        from server.auth import tenant_middleware as tm
        if hasattr(tm.g, 'tenant_id'):
            delattr(tm.g, 'tenant_id')

        with patch('server.auth.tenant_middleware.get_request', side_effect=Exception("boom")):
            tenant_id = tenant_middleware.setup_tenant_context()
            assert_is_none(tenant_id, "Should return None when get_request fails")
            assert_false(hasattr(tm.g, 'tenant_id'), "Should not set module g when no tenant")

    def test_setup_tenant_context_extract_exception(self, tenant_middleware, mock_request):
        """setup_tenant_context should handle extract_tenant_id exceptions gracefully."""
        from server.auth import tenant_middleware as tm
        if hasattr(tm.g, 'tenant_id'):
            delattr(tm.g, 'tenant_id')

        with patch.object(tenant_middleware, 'extract_tenant_id', side_effect=Exception("extract fails")):
            tenant_id = tenant_middleware.setup_tenant_context(req=mock_request)
            assert_is_none(tenant_id, "Should return None when extraction fails")
            assert_false(hasattr(tm.g, 'tenant_id'), "Should not set module g when extraction fails")

    def test_require_tenant_decorator_missing_tenant_nontuple(self, tenant_middleware, mock_request):
        """require_tenant should wrap non-tuple jsonify responses with status code."""
        mock_request.headers = {}
        mock_request.session = None
        mock_request.remote_addr = "127.0.0.1"
        mock_request.endpoint = "ep"

        @tenant_middleware.require_tenant
        def test_func():
            return "success"

        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify', side_effect=lambda d: {"payload": d}):
                result = test_func()
                assert_equals(result, ({"payload": {'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'}}, 400), "Should wrap jsonify result with 400")

    def test_enforce_tenant_isolation_decorator_missing_tenant_nontuple(self, tenant_middleware, mock_request):
        """enforce_tenant_isolation should wrap non-tuple jsonify on missing tenant."""
        mock_request.headers = {}
        mock_request.session = None
        mock_request.endpoint = "ep"

        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"

        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify', side_effect=lambda d: d):
                result = test_func()
                assert_equals(result, ({'error': 'Tenant ID required', 'code': 'MISSING_TENANT_ID'}, 400), "Should wrap with 400")

    def test_enforce_tenant_isolation_decorator_violation_nontuple(self, tenant_middleware, mock_request):
        """enforce_tenant_isolation should wrap non-tuple jsonify on tenant violation (403)."""
        mock_request.headers = {"X-BAS-Tenant": "tenant_x"}
        mock_request.session = Mock()
        mock_request.session.tenant_id = "tenant_y"
        mock_request.session.username = "user"
        mock_request.session.user_id = "uid"
        mock_request.remote_addr = "1.2.3.4"

        @tenant_middleware.enforce_tenant_isolation
        def test_func():
            return "success"

        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.jsonify', side_effect=lambda d: d):
                result = test_func()
                assert_equals(result, ({'error': 'Access denied to tenant', 'code': 'TENANT_ACCESS_DENIED'}, 403), "Should wrap with 403")

    def test_require_device_access_decorator_missing_tenant_context_nontuple(self, tenant_middleware, mock_request):
        """require_device_access should wrap non-tuple jsonify on missing tenant context."""
        @tenant_middleware.require_device_access
        def test_func():
            return "success"

        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                mock_g.tenant_id = None
                with patch('server.auth.tenant_middleware.jsonify', side_effect=lambda d: d):
                    result = test_func()
                    assert_equals(result, ({'error': 'Tenant ID not available', 'code': 'TENANT_ID_MISSING'}, 400), "Should wrap with 400")

    def test_require_device_access_decorator_missing_device_id_nontuple(self, tenant_middleware, mock_request):
        """require_device_access should wrap non-tuple jsonify on missing device_id."""
        mock_request.is_json = False
        mock_request.json = None
        mock_request.args = {}
        mock_request.endpoint = "ep"

        @tenant_middleware.require_device_access
        def test_func():
            return "success"

        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                mock_g.tenant_id = "tenant"
                with patch('server.auth.tenant_middleware.jsonify', side_effect=lambda d: d):
                    result = test_func()
                    assert_equals(result, ({'error': 'Device ID required', 'code': 'MISSING_DEVICE_ID'}, 400), "Should wrap with 400")

    def test_require_device_access_decorator_no_tenant_context(self, tenant_middleware, mock_request):
        """Test require_device_access decorator without tenant context."""
        @tenant_middleware.require_device_access
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                    mock_g.tenant_id = None  # No tenant context
                    mock_jsonify.return_value = ({"error": "Tenant ID not available"}, 400)
                    
                    result = test_func()
                    
                    assert_equals(result, ({"error": "Tenant ID not available"}, 400), "Should return error")
    
    def test_require_device_access_decorator_missing_device_id(self, tenant_middleware, mock_request):
        """Test require_device_access decorator with missing device ID."""
        mock_request.is_json = False
        mock_request.json = None
        mock_request.args = {}  # No device_id in args either
        
        @tenant_middleware.require_device_access
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                    mock_g.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
                    mock_jsonify.return_value = ({"error": "Device ID required"}, 400)
                    
                    result = test_func()
                    
                    assert_equals(result, ({"error": "Device ID required"}, 400), "Should return error")
    
    def test_require_device_access_decorator_device_id_from_args(self, tenant_middleware, mock_request):
        """Test require_device_access decorator with device ID from URL args."""
        mock_request.is_json = False
        mock_request.json = None
        mock_request.args = {"device_id": "device_456"}
        
        @tenant_middleware.require_device_access
        def test_func():
            return "success"
        
        with patch('server.auth.tenant_middleware.request', mock_request):
            with patch('server.auth.tenant_middleware.g') as mock_g:
                mock_g.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
                
                result = test_func()
                
                assert_equals(result, "success", "Should call decorated function")
                assert_equals(mock_g.device_id, "device_456", "Should set device_id from args")


@pytest.mark.auth
@pytest.mark.unit
class TestSetupTenantMiddleware:
    """Test cases for setup_tenant_middleware function."""
    
    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        app = Flask(__name__)
        return app
    
    @pytest.fixture
    def auth_config(self):
        """Create auth config for testing."""
        config = Mock(spec=AuthConfig)
        config.tenant_id_header = "X-BAS-Tenant"
        return config
    
    @pytest.fixture
    def audit_service(self):
        """Create mock audit service."""
        return Mock()
    
    def test_setup_tenant_middleware(self, app, auth_config, audit_service):
        """Test setting up tenant middleware."""
        middleware = setup_tenant_middleware(app, auth_config, audit_service)
        
        assert_is_instance(middleware, TenantMiddleware, "Should return TenantMiddleware instance")
        assert_true(hasattr(app, 'tenant_middleware'), "Should attach middleware to app")
        assert_equals(app.tenant_middleware, middleware, "Should store middleware in app")
    
    def test_setup_tenant_middleware_no_audit_service(self, app, auth_config):
        """Test setting up tenant middleware without audit service."""
        middleware = setup_tenant_middleware(app, auth_config)
        
        assert_is_instance(middleware, TenantMiddleware, "Should return TenantMiddleware instance")
        assert_is_none(middleware.audit_service, "Should have None audit service")
    
    def test_setup_tenant_middleware_before_request_handler(self, app, auth_config):
        """Test that setup_tenant_middleware registers before_request handler."""
        middleware = setup_tenant_middleware(app, auth_config)
        
        # Check that before_request handler was registered
        before_request_handlers = app.before_request_funcs.get(None, [])
        assert_true(len(before_request_handlers) > 0, "Should register before_request handler")


@pytest.mark.auth
@pytest.mark.unit
class TestConvenienceDecorators:
    """Test cases for convenience decorators."""
    
    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        app = Flask(__name__)
        return app
    
    @pytest.fixture
    def auth_config(self):
        """Create auth config for testing."""
        config = Mock(spec=AuthConfig)
        config.tenant_id_header = "X-BAS-Tenant"
        return config
    
    @pytest.fixture
    def audit_service(self):
        """Create mock audit service."""
        return Mock()
    
    def test_require_tenant_decorator_with_middleware(self, app, auth_config, audit_service):
        """Test require_tenant decorator with configured middleware."""
        middleware = setup_tenant_middleware(app, auth_config, audit_service)
        
        @require_tenant
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.request') as mock_request:
                with patch('server.auth.tenant_middleware.g') as mock_g:
                    mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
                    
                    result = test_route()
                    
                    assert_equals(result, "success", "Should call decorated function")
                    assert_equals(mock_g.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id in context")
    
    def test_require_tenant_decorator_no_middleware(self, app):
        """Test require_tenant decorator without configured middleware."""
        @require_tenant
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant middleware not configured"}, 500)
                
                result = test_route()
                
                assert_equals(result, ({"error": "Tenant middleware not configured"}, 500), "Should return error")
    
    def test_enforce_tenant_isolation_decorator_with_middleware(self, app, auth_config, audit_service):
        """Test enforce_tenant_isolation decorator with configured middleware."""
        middleware = setup_tenant_middleware(app, auth_config, audit_service)
        
        @enforce_tenant_isolation
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.request') as mock_request:
                with patch('server.auth.tenant_middleware.g') as mock_g:
                    mock_request.headers = {"X-BAS-Tenant": "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"}
                    mock_request.session = None  # No session (public endpoint)
                    
                    result = test_route()
                    
                    assert_equals(result, "success", "Should call decorated function")
                    assert_equals(mock_g.tenant_id, "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b", "Should set tenant_id in context")
    
    def test_enforce_tenant_isolation_decorator_no_middleware(self, app):
        """Test enforce_tenant_isolation decorator without configured middleware."""
        @enforce_tenant_isolation
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant middleware not configured"}, 500)
                
                result = test_route()
                
                assert_equals(result, ({"error": "Tenant middleware not configured"}, 500), "Should return error")
    
    def test_require_device_access_decorator_with_middleware(self, app, auth_config, audit_service):
        """Test require_device_access decorator with configured middleware."""
        middleware = setup_tenant_middleware(app, auth_config, audit_service)
        
        @require_device_access
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.request') as mock_request:
                with patch('server.auth.tenant_middleware.g') as mock_g:
                    mock_request.is_json = True
                    mock_request.json = {"device_id": "device_123"}
                    mock_g.tenant_id = "e6f7a8b9-c0d1-4e2f-3a4b-5c6d7e8f9a0b"
                    
                    result = test_route()
                    
                    assert_equals(result, "success", "Should call decorated function")
                    assert_equals(mock_g.device_id, "device_123", "Should set device_id in context")
    
    def test_require_device_access_decorator_no_middleware(self, app):
        """Test require_device_access decorator without configured middleware."""
        @require_device_access
        def test_route():
            return "success"
        
        with app.app_context():
            with patch('server.auth.tenant_middleware.jsonify') as mock_jsonify:
                mock_jsonify.return_value = ({"error": "Tenant middleware not configured"}, 500)
                
                result = test_route()
                
                assert_equals(result, ({"error": "Tenant middleware not configured"}, 500), "Should return error")
