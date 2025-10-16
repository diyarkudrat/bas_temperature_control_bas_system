"""
Unit tests for authentication middleware using pytest.
"""

import pytest
from unittest.mock import Mock, patch

from auth.middleware import require_auth, add_security_headers, _has_permission, log_request_info, handle_auth_error
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
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
            ctx.request.headers = {}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'short'}  # Too short
            
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
            ctx.request.headers = {}  # No session ID
            
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
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {}  # No session ID in headers
            ctx.request.cookies = {'bas_session_id': 'test_session'}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'header_session'}
            ctx.request.cookies = {'bas_session_id': 'cookie_session'}
            
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
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function logs access in shadow mode
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            ctx.request.session = None
            ctx.request.audit_logger = Mock()
            
            result = test_endpoint()
            assert_equals(result, "success", "Should allow access in shadow mode")
            # Verify audit logging was called
            ctx.request.audit_logger.log_session_access.assert_called_once_with('test_session', 'test_endpoint')

    def test_require_auth_shadow_mode_no_audit_logger(self):
        """Test require_auth decorator in shadow mode without audit logger."""
        # Arrange - Set up mock request with shadow mode but no audit logger
        from flask import Flask
        app = Flask(__name__)
        
        @require_auth("admin")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function doesn't crash without audit logger
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "shadow"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
        
        @require_auth("operator")
        def test_endpoint():
            return "success"
        
        # Act & Assert - Test that function logs access
        with app.test_request_context('/test_endpoint') as ctx:
            ctx.request.auth_config = Mock()
            ctx.request.auth_config.auth_enabled = True
            ctx.request.auth_config.auth_mode = "enforced"
            ctx.request.headers = {'X-Session-ID': 'test_session'}
            
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
