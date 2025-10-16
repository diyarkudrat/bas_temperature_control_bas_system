"""Flask middleware for authentication."""

import logging
from functools import wraps
from flask import request, jsonify
from .exceptions import AuthError

logger = logging.getLogger(__name__)

def require_auth(required_role="operator"):
    """Decorator for protected endpoints."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.debug(f"Checking authentication for endpoint: {request.endpoint}")
            
            # Validate required_role parameter
            if required_role not in ['operator', 'admin', 'read-only']:
                logger.error(f"Invalid required_role: {required_role}")
                return jsonify({"error": "Invalid role configuration", "code": "CONFIG_ERROR"}), 500
            
            # Skip auth if disabled
            if not hasattr(request, 'auth_config') or not request.auth_config or not request.auth_config.auth_enabled:
                logger.debug("Authentication disabled, allowing access")
                return f(*args, **kwargs)
            
            # Shadow mode - log but don't block
            if request.auth_config.auth_mode == "shadow":
                logger.info(f"Shadow mode: logging access to {request.endpoint}")
                session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')
                session = getattr(request, 'session', None)
                if hasattr(request, 'audit_logger'):
                    request.audit_logger.log_session_access(session_id, request.endpoint)
                return f(*args, **kwargs)
            
            # Enforced mode - require valid session
            logger.debug("Authentication enforced, checking session")
            session_id = request.headers.get('X-Session-ID') or request.cookies.get('bas_session_id')
            
            # Validate session ID format
            if not session_id or not isinstance(session_id, str) or len(session_id) < 10:
                logger.warning(f"Invalid session ID format for {request.endpoint}")
                return jsonify({
                    "error": "Invalid session ID",
                    "message": "Please login again",
                    "code": "INVALID_SESSION_ID"
                }), 401
            
            session_manager = getattr(request, 'session_manager', None)
            if not session_manager:
                logger.error("Session manager not available")
                return jsonify({"error": "Authentication system not available", "code": "AUTH_SYSTEM_ERROR"}), 500
            
            session = session_manager.validate_session(session_id, request)
            if not session:
                logger.warning(f"Invalid or expired session for {request.endpoint}")
                return jsonify({
                    "error": "Invalid or expired session",
                    "message": "Please login again",
                    "code": "SESSION_INVALID"
                }), 401
            
            # Check role permissions
            if not _has_permission(session.role, required_role):
                logger.warning(f"Insufficient permissions for {session.username} ({session.role}) to access {request.endpoint} (requires {required_role})")
                return jsonify({
                    "error": "Insufficient permissions",
                    "message": f"{session.role} role cannot perform this action",
                    "code": "PERMISSION_DENIED"
                }), 403
            
            # Update last access
            session_manager.update_last_access(session_id)
            
            # Add session to request context
            request.session = session
            
            # Log access
            if hasattr(request, 'audit_logger'):
                request.audit_logger.log_session_access(session_id, request.endpoint)
            
            logger.debug(f"Authentication successful for {session.username} accessing {request.endpoint}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def _has_permission(user_role: str, required_role: str) -> bool:
    """Check if user role has permission for required role."""
    logger.debug(f"Checking permission: {user_role} -> {required_role}")
    
    role_hierarchy = {
        "read-only": 1,
        "operator": 2,
        "admin": 3
    }
    
    user_level = role_hierarchy.get(user_role, 0)
    required_level = role_hierarchy.get(required_role, 0)
    
    has_permission = user_level >= required_level
    logger.debug(f"Permission check result: {has_permission}")
    return has_permission

def add_security_headers(response):
    """Add security headers to response."""
    logger.debug("Adding security headers to response")
    
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    logger.debug("Security headers added successfully")
    return response

def log_request_info():
    """Log request information for debugging."""
    logger.debug(f"Request: {request.method} {request.path}")
    logger.debug(f"IP: {request.remote_addr}")
    logger.debug(f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.debug(f"Session-ID: {request.headers.get('X-Session-ID', 'None')}")

def handle_auth_error(error):
    """Handle authentication errors."""
    logger.error(f"Authentication error: {error}")
    
    if isinstance(error, AuthError):
        return jsonify({
            "error": "Authentication error",
            "message": str(error),
            "code": "AUTH_ERROR"
        }), 401
    else:
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "code": "INTERNAL_ERROR"
        }), 500
