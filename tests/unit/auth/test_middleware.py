from __future__ import annotations

import time
from typing import Dict, Any

import pytest
from flask import Flask, request, jsonify

from server.auth.middleware import require_auth


class _DummySession:
    def __init__(self, username: str, user_id: str, role: str, tenant_id: str | None = None):
        self.username = username
        self.user_id = user_id
        self.role = role
        self.tenant_id = tenant_id


class _DummySessionManager:
    def __init__(self, valid_id: str, session: _DummySession | None):
        self._valid = valid_id
        self._session = session

    def validate_session(self, sid: str, req):  # noqa: ARG002
        return self._session if sid == self._valid else None

    def update_last_access(self, sid: str):  # noqa: ARG002
        return True


class _MockProvider:
    def __init__(self, claims: Dict[str, Any] | None = None, roles: list[str] | None = None, fail: Exception | None = None):
        self._claims = claims
        self._roles = roles or []
        self._fail = fail

    def verify_token(self, token: str):  # noqa: ARG002
        if self._fail:
            raise self._fail
        return self._claims or {}

    def get_user_roles(self, uid: str):  # noqa: ARG002
        return list(self._roles)

    def healthcheck(self):
        return {"status": "ok"}


def _make_app(auth_config_overrides: Dict[str, Any] | None = None):
    app = Flask(__name__)

    class Cfg:
        auth_enabled = True
        auth_mode = "enforced"
        tenant_id_header = "X-BAS-Tenant"
        allow_session_fallback = False

    cfg = Cfg()
    if auth_config_overrides:
        for k, v in auth_config_overrides.items():
            setattr(cfg, k, v)

    @app.before_request
    def inject():
        request.auth_config = cfg
        # request.auth_provider & request.session_manager set in tests

    @app.route("/protected")
    @require_auth(required_role="operator", require_tenant=False)
    def protected():
        return jsonify({"ok": True})

    @app.route("/tenant")
    @require_auth(required_role="operator", require_tenant=True)
    def protected_tenant():
        return jsonify({"ok": True, "tenant": getattr(request, 'tenant_id', None)})

    return app


def test_jwt_auth_valid(client=None):  # noqa: ARG001
    app = _make_app()
    provider = _MockProvider(claims={"sub": "u1"}, roles=["operator"])

    with app.test_client() as c:
        headers = {"Authorization": "Bearer token", "X-BAS-Tenant": "t1"}
        with app.test_request_context():
            pass
        # inject provider per request via environ_overrides
        def _inject_provider(environ):
            return environ

        # monkeypatching context by setting on request is not trivial here; instead, use before_request to set attribute via after_open
        @app.before_request
        def _set_provider():
            request.auth_provider = provider

        rv = c.get("/protected", headers=headers)
        assert rv.status_code == 200


def test_jwt_auth_invalid_no_fallback():
    app = _make_app({"allow_session_fallback": False})
    provider = _MockProvider(fail=ValueError("expired"))
    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            request.auth_provider = provider

        rv = c.get("/protected", headers={"Authorization": "Bearer bad"})
        assert rv.status_code == 401
        data = rv.get_json()
        assert data["code"] in {"INVALID_TOKEN", "TOKEN_EXPIRED"}


def test_session_fallback_when_enabled():
    app = _make_app({"allow_session_fallback": True})
    provider = _MockProvider(fail=ValueError("boom"))
    good_sid = "1234567890abcdef"
    session = _DummySession("alice", "u1", "operator")
    sm = _DummySessionManager(good_sid, session)

    with app.test_client() as c:
        @app.before_request
        def _set_provider_and_session():
            request.auth_provider = provider
            request.session_manager = sm

        rv = c.get("/protected", headers={"Authorization": "Bearer bad", "X-Session-ID": good_sid})
        assert rv.status_code == 200


def test_jwt_permission_denied():
    app = _make_app()
    provider = _MockProvider(claims={"sub": "u2"}, roles=["read-only"])  # needs operator
    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            request.auth_provider = provider
        rv = c.get("/protected", headers={"Authorization": "Bearer t"})
        assert rv.status_code == 403


def test_jwt_tenant_required_header_missing():
    app = _make_app()
    provider = _MockProvider(claims={"sub": "u3"}, roles=["operator"])  # good role
    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            request.auth_provider = provider
        rv = c.get("/tenant", headers={"Authorization": "Bearer t"})
        assert rv.status_code == 400
        data = rv.get_json()
        assert data["code"] == "MISSING_TENANT_ID"

"""
Unit tests for authentication middleware using pytest.
"""

import pytest
from unittest.mock import Mock, patch

from auth.middleware import (
    require_auth,
    add_security_headers,
    _has_permission,
    log_request_info,
    handle_auth_error,
    _enforce_tenant_isolation,
    _audit_auth_failure,
    _audit_permission_denied,
    _audit_tenant_violation,
)
from auth.exceptions import AuthError
from tests.utils.assertions import assert_equals, assert_true, assert_false


@pytest.mark.auth
@pytest.mark.unit
class TestAuthMiddleware:
    """Test authentication middleware with 100% coverage."""

    def test_has_permission_read_only_to_read_only(self):
        """Test permission check: read-only to read-only."""
        # Arrange - Set up test data
        user_role = "read-only"
        required_role = "read-only"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Read-only user should have read-only permission")

    def test_has_permission_operator_to_read_only(self):
        """Test permission check: operator to read-only."""
        # Arrange - Set up test data
        user_role = "operator"
        required_role = "read-only"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Operator should have read-only permission")

    def test_has_permission_admin_to_read_only(self):
        """Test permission check: admin to read-only."""
        # Arrange - Set up test data
        user_role = "admin"
        required_role = "read-only"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Admin should have read-only permission")

    def test_has_permission_read_only_to_operator(self):
        """Test permission check: read-only to operator."""
        # Arrange - Set up test data
        user_role = "read-only"
        required_role = "operator"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_false(has_permission, "Read-only user should not have operator permission")

    def test_has_permission_operator_to_operator(self):
        """Test permission check: operator to operator."""
        # Arrange - Set up test data
        user_role = "operator"
        required_role = "operator"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Operator should have operator permission")

    def test_has_permission_admin_to_operator(self):
        """Test permission check: admin to operator."""
        # Arrange - Set up test data
        user_role = "admin"
        required_role = "operator"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Admin should have operator permission")

    def test_has_permission_read_only_to_admin(self):
        """Test permission check: read-only to admin."""
        # Arrange - Set up test data
        user_role = "read-only"
        required_role = "admin"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_false(has_permission, "Read-only user should not have admin permission")

    def test_has_permission_operator_to_admin(self):
        """Test permission check: operator to admin."""
        # Arrange - Set up test data
        user_role = "operator"
        required_role = "admin"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_false(has_permission, "Operator should not have admin permission")

    def test_has_permission_admin_to_admin(self):
        """Test permission check: admin to admin."""
        # Arrange - Set up test data
        user_role = "admin"
        required_role = "admin"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_true(has_permission, "Admin should have admin permission")

    def test_has_permission_unknown_role(self):
        """Test permission check with unknown role."""
        # Arrange - Set up test data
        user_role = "unknown"
        required_role = "read-only"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result
        assert_false(has_permission, "Unknown role should not have permission")

    def test_has_permission_unknown_required_role(self):
        """Test permission check with unknown required role."""
        # Arrange - Set up test data
        user_role = "admin"
        required_role = "unknown"
        
        # Act - Check permission
        has_permission = _has_permission(user_role, required_role)
        
        # Assert - Verify result (current implementation returns True for unknown required roles)
        assert_true(has_permission, "Admin should have permission even for unknown required role")

    def test_add_security_headers(self):
        """Test adding security headers to response."""
        # Arrange - Create mock response
        mock_response = Mock()
        mock_response.headers = {}
        
        # Act - Add security headers
        result = add_security_headers(mock_response)
        
        # Assert - Verify headers were added
        assert_equals(result, mock_response, "Should return the same response object")
        assert 'X-Content-Type-Options' in mock_response.headers
        assert 'X-Frame-Options' in mock_response.headers
        assert 'X-XSS-Protection' in mock_response.headers
        assert 'Strict-Transport-Security' in mock_response.headers
        assert 'Content-Security-Policy' in mock_response.headers
        assert 'Referrer-Policy' in mock_response.headers
        assert 'Permissions-Policy' in mock_response.headers

    def test_log_request_info(self):
        """Test logging request information."""
        # Arrange - Set up Flask app context
        from flask import Flask
        app = Flask(__name__)
        
        # Act & Assert - Test that function doesn't raise exceptions
        with app.test_request_context():
            # This function just logs, so we test it doesn't raise exceptions
            log_request_info()

    def test_handle_auth_error_auth_error(self):
        """Test handling AuthError."""
        # Arrange - Set up Flask app context and error
        from flask import Flask
        app = Flask(__name__)
        error = AuthError("Test auth error")
        
        # Act - Handle the error
        with app.app_context():
            response, status_code = handle_auth_error(error)
            
            # Assert - Verify response
            assert_equals(status_code, 401, "AuthError should return 401 status")

    def test_handle_auth_error_other_error(self):
        """Test handling non-AuthError."""
        # Arrange - Set up Flask app context and error
        from flask import Flask
        app = Flask(__name__)
        error = ValueError("Test value error")
        
        # Act - Handle the error
        with app.app_context():
            response, status_code = handle_auth_error(error)
            
            # Assert - Verify response
            assert_equals(status_code, 500, "Non-AuthError should return 500 status")

    def test_require_auth_decorator_disabled_auth(self):
        """Test require_auth decorator when auth is disabled."""
        # Arrange - Set up mock request with disabled auth
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function executes when auth is disabled
        with app.test_request_context() as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = False
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access when auth is disabled")

    def test_require_auth_decorator_shadow_mode(self):
        """Test require_auth decorator in shadow mode."""
        # Arrange - Set up mock request with shadow mode
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function executes in shadow mode
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.session = None
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access in shadow mode")

    def test_require_auth_decorator_no_session_id(self):
        """Test require_auth decorator when no session ID is provided."""
        # Arrange - Set up mock request without session ID
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns auth error
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 401, "Should return 401 when no session ID provided")

    def test_require_auth_decorator_no_session_manager(self):
        """Test require_auth decorator when session manager is not available."""
        # Arrange - Set up mock request without session manager
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns system error
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.session_manager = None
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 500, "Should return 500 when session manager not available")

    def test_require_auth_decorator_invalid_session(self):
        """Test require_auth decorator with invalid session."""
        # Arrange - Set up mock request with invalid session
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns session error
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = None
            ctx.request.session_manager = mock_session_manager
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 401, "Should return 401 when session is invalid")

    def test_require_auth_decorator_insufficient_permissions(self):
        """Test require_auth decorator with insufficient permissions."""
        # Arrange - Set up mock request with insufficient permissions
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns permission error
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 403, "Should return 403 when permissions are insufficient")

    def test_require_auth_decorator_success(self):
        """Test require_auth decorator with successful authentication."""
        # Arrange - Set up mock request with valid session and permissions
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function executes successfully
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with valid session and permissions")

    def test_require_auth_invalid_role(self):
        """Test require_auth decorator with invalid required role."""
        # Arrange - Set up mock request with invalid role
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("invalid_role")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns config error
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 500, "Should return 500 for invalid role configuration")

    def test_require_auth_invalid_session_id_format(self):
        """Test require_auth decorator with invalid session ID format."""
        # Arrange - Set up mock request with invalid session ID
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns invalid session error
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'short'}) as ctx:  # Too short
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 401, "Should return 401 for invalid session ID format")

    def test_require_auth_no_session_id(self):
        """Test require_auth decorator when no session ID is provided."""
        # Arrange - Set up mock request without session ID
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function returns auth error
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            # No session ID in headers
            
            response, status_code = test_endpoint()
            assert_equals(status_code, 401, "Should return 401 when no session ID provided")

    def test_require_auth_session_id_from_cookie(self):
        """Test require_auth decorator getting session ID from cookie."""
        # Arrange - Set up mock request with session ID in cookie
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function gets session ID from cookie
        with app.test_request_context('/test_endpoint') as ctx:
            # Manually set cookies on the request
            ctx.request.cookies = {'bas_session_id': 'test_session'}
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            # No session ID in headers
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with session ID from cookie")

    def test_require_auth_session_id_from_header_priority(self):
        """Test require_auth decorator prioritizes header over cookie."""
        # Arrange - Set up mock request with session ID in both header and cookie
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function uses header session ID
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'header_session'}) as ctx:
            # Manually set cookies on the request
            ctx.request.cookies = {'bas_session_id': 'cookie_session'}
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            # Verify that header session ID was used (not cookie)
            mock_session_manager.validate_session.assert_called_once_with('header_session', ctx.request)
            assert_equals(result, "success", "Should use header session ID over cookie")

    def test_require_auth_shadow_mode_logging(self):
        """Test require_auth decorator in shadow mode with logging."""
        # Arrange - Set up mock request with shadow mode
        from flask import Flask
        app = Flask(__name__)
        
        @app.route('/test_endpoint')
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function logs access in shadow mode
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.session = None
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access in shadow mode")
            # Verify audit logging was called
            ctx.request.audit_logger.log_session_access.assert_called_once_with('test_session', 'test_endpoint')

    def test_require_auth_with_tenant_success(self):
        """require_auth with tenant enforcement: success path sets g.tenant_id."""
        from flask import Flask, g
        app = Flask(__name__)

        @require_auth("operator", require_tenant=True)
        def test_endpoint():
            return "success"

        with app.test_request_context(
            '/test_endpoint',
            headers={'X-Session-ID': 'test_session_123', 'X-BAS-Tenant': 'tenant-1'}
        ) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'

            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            mock_session.user_id = "uid-1"
            mock_session.tenant_id = "tenant-1"

            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()

            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with valid tenant")
            assert g.tenant_id == "tenant-1"
            mock_session_manager.update_last_access.assert_called_once_with('test_session_123')

    def test_require_auth_with_tenant_missing_header(self):
        """require_auth with tenant enforcement: missing tenant header => 400."""
        from flask import Flask
        app = Flask(__name__)

        @require_auth("operator", require_tenant=True)
        def test_endpoint():
            return "success"

        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session_123'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'

            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            mock_session.user_id = "uid-1"
            mock_session.tenant_id = "tenant-1"

            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager

            response, status_code = test_endpoint()
            assert_equals(status_code, 400, "Should return 400 when tenant header missing")

    def test_require_auth_with_tenant_no_session_tenant(self):
        """require_auth with tenant enforcement: session has no tenant => 400."""
        from flask import Flask
        app = Flask(__name__)

        @require_auth("operator", require_tenant=True)
        def test_endpoint():
            return "success"

        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session_123', 'X-BAS-Tenant': 'tenant-1'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'

            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            mock_session.user_id = "uid-1"
            mock_session.tenant_id = None

            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager

            response, status_code = test_endpoint()
            assert_equals(status_code, 400, "Should return 400 when session lacks tenant")

    def test_require_auth_with_tenant_mismatch(self):
        """require_auth with tenant enforcement: tenant mismatch => 403."""
        from flask import Flask
        app = Flask(__name__)

        @require_auth("operator", require_tenant=True)
        def test_endpoint():
            return "success"

        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session_123', 'X-BAS-Tenant': 'tenant-2'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'

            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            mock_session.user_id = "uid-1"
            mock_session.tenant_id = "tenant-1"

            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager

            response, status_code = test_endpoint()
            assert_equals(status_code, 403, "Should return 403 when tenant mismatch")

    def test_enforce_tenant_isolation_missing_header(self):
        """_enforce_tenant_isolation returns 400 when tenant header is missing."""
        from flask import Flask
        app = Flask(__name__)
        session = Mock()
        session.username = 'user'
        session.user_id = 'uid'
        session.tenant_id = 'tenant-1'

        with app.test_request_context('/endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'
            # No tenant header
            result, status = _enforce_tenant_isolation(session, ctx.request)
            assert_equals(status, 400)

    def test_enforce_tenant_isolation_no_session_tenant(self):
        """_enforce_tenant_isolation returns 400 when session has no tenant."""
        from flask import Flask
        app = Flask(__name__)
        session = Mock()
        session.username = 'user'
        session.user_id = 'uid'
        session.tenant_id = None

        with app.test_request_context('/endpoint', headers={'X-BAS-Tenant': 'tenant-1'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'
            result, status = _enforce_tenant_isolation(session, ctx.request)
            assert_equals(status, 400)

    def test_enforce_tenant_isolation_mismatch(self):
        """_enforce_tenant_isolation returns 403 when tenant IDs mismatch."""
        from flask import Flask
        app = Flask(__name__)
        session = Mock()
        session.username = 'user'
        session.user_id = 'uid'
        session.tenant_id = 'tenant-1'

        with app.test_request_context('/endpoint', headers={'X-BAS-Tenant': 'tenant-2'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'
            result, status = _enforce_tenant_isolation(session, ctx.request)
            assert_equals(status, 403)

    def test_enforce_tenant_isolation_success(self):
        """_enforce_tenant_isolation returns True and sets g.tenant_id on success."""
        from flask import Flask, g
        app = Flask(__name__)
        session = Mock()
        session.username = 'user'
        session.user_id = 'uid'
        session.tenant_id = 'tenant-1'

        with app.test_request_context('/endpoint', headers={'X-BAS-Tenant': 'tenant-1'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'
            result = _enforce_tenant_isolation(session, ctx.request)
            assert_true(result is True)
            assert_equals(g.tenant_id, 'tenant-1')

    def test_enforce_tenant_isolation_exception(self):
        """_enforce_tenant_isolation returns 500 on unexpected exception."""
        from flask import Flask
        app = Flask(__name__)

        class BadSession:
            # tenant_id missing/None, username access raises to trigger except path
            def __getattr__(self, name):
                if name == 'tenant_id':
                    return None
                if name in ('username', 'user_id'):
                    raise RuntimeError('boom')
                raise AttributeError

        bad_session = BadSession()

        with app.test_request_context('/endpoint', headers={'X-BAS-Tenant': 'tenant-1'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.tenant_id_header = 'X-BAS-Tenant'
            response, status = _enforce_tenant_isolation(bad_session, ctx.request)
            assert_equals(status, 500)

    def test_audit_auth_failure_firestore(self):
        """_audit_auth_failure uses firestore audit when available."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_auth_failure('REASON', '1.2.3.4', 'endpoint')
            firestore.log_event.assert_called_once()

    def test_audit_auth_failure_fallback(self):
        """_audit_auth_failure falls back to sqlite audit when firestore unavailable."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            audit_logger = Mock()
            audit_logger.firestore_audit = None
            audit_logger.log_auth_failure = Mock()
            ctx.request.audit_logger = audit_logger

            _audit_auth_failure('REASON', '1.2.3.4', 'endpoint')
            audit_logger.log_auth_failure.assert_called_once()

    def test_audit_auth_failure_exception(self):
        """_audit_auth_failure swallows exceptions from audit sink."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            firestore.log_event.side_effect = Exception('boom')
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_auth_failure('REASON', '1.2.3.4', 'endpoint')

    def test_audit_permission_denied_firestore(self):
        """_audit_permission_denied uses firestore audit when available."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_permission_denied('user', 'uid', '1.2.3.4', 'endpoint', 'REASON')
            firestore.log_event.assert_called_once()

    def test_audit_permission_denied_fallback(self):
        """_audit_permission_denied falls back when firestore unavailable."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            audit_logger = Mock()
            audit_logger.firestore_audit = None
            audit_logger.log_permission_denied = Mock()
            ctx.request.audit_logger = audit_logger

            _audit_permission_denied('user', 'uid', '1.2.3.4', 'endpoint', 'REASON')
            audit_logger.log_permission_denied.assert_called_once()

    def test_audit_permission_denied_exception(self):
        """_audit_permission_denied swallows exceptions from audit sink."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            firestore.log_event.side_effect = Exception('boom')
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_permission_denied('user', 'uid', '1.2.3.4', 'endpoint', 'REASON')

    def test_audit_tenant_violation_firestore(self):
        """_audit_tenant_violation uses firestore audit when available."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_tenant_violation('uid', 'user', '1.2.3.4', 'tenant-x', 'tenant-y')
            firestore.log_event.assert_called_once()

    def test_audit_tenant_violation_fallback(self):
        """_audit_tenant_violation falls back when firestore unavailable."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            audit_logger = Mock()
            audit_logger.firestore_audit = None
            audit_logger.log_tenant_violation = Mock()
            ctx.request.audit_logger = audit_logger

            _audit_tenant_violation('uid', 'user', '1.2.3.4', 'tenant-x', 'tenant-y')
            audit_logger.log_tenant_violation.assert_called_once()

    def test_audit_tenant_violation_exception(self):
        """_audit_tenant_violation swallows exceptions from audit sink."""
        from flask import Flask
        app = Flask(__name__)
        with app.test_request_context('/endpoint', headers={'User-Agent': 'UA'}) as ctx:
            firestore = Mock()
            firestore.log_event.side_effect = Exception('boom')
            audit_logger = Mock()
            audit_logger.firestore_audit = firestore
            ctx.request.audit_logger = audit_logger

            _audit_tenant_violation('uid', 'user', '1.2.3.4', 'tenant-x', 'tenant-y')

    def test_require_auth_shadow_mode_no_audit_logger(self):
        """Test require_auth decorator in shadow mode without audit logger."""
        # Arrange - Set up mock request with shadow mode but no audit logger
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function doesn't crash without audit logger
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.session = None
            # No audit_logger attribute
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access in shadow mode without audit logger")

    def test_require_auth_updates_last_access(self):
        """Test require_auth decorator updates last access time."""
        # Arrange - Set up mock request with valid session
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function updates last access
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with valid session")
            # Verify last access was updated
            mock_session_manager.update_last_access.assert_called_once_with('test_session')

    def test_require_auth_adds_session_to_request(self):
        """Test require_auth decorator adds session to request context."""
        # Arrange - Set up mock request with valid session
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function adds session to request
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with valid session")
            # Verify session was added to request
            assert_equals(ctx.request.session, mock_session)

    def test_require_auth_logs_access(self):
        """Test require_auth decorator logs access."""
        # Arrange - Set up mock request with valid session
        from flask import Flask
        app = Flask(__name__)
        
        @app.route('/test_endpoint')
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function logs access
        with app.test_request_context('/test_endpoint', headers={'X-Session-ID': 'test_session'}) as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            
            mock_session = Mock()
            mock_session.role = "operator"
            mock_session.username = "testuser"
            
            mock_session_manager = Mock()
            mock_session_manager.validate_session.return_value = mock_session
            ctx.request.session_manager = mock_session_manager
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access with valid session")
            # Verify access was logged
            ctx.request.audit_logger.log_session_access.assert_called_once_with('test_session', 'test_endpoint')
