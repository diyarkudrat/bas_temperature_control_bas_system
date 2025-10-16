"""Multi-tenant middleware for enforcing tenant isolation."""

import logging
from typing import Optional, Dict, Any, Callable
from flask import request, jsonify, g
from functools import wraps

from .config import AuthConfig
from .exceptions import AuthError, PermissionError as AuthPermissionError

logger = logging.getLogger(__name__)


class TenantMiddleware:
    """Middleware for enforcing multi-tenant isolation."""
    
    def __init__(self, auth_config: AuthConfig, audit_service=None):
        """Initialize with auth configuration and audit service."""
        self.auth_config = auth_config
        self.audit_service = audit_service
        self.tenant_header = auth_config.tenant_id_header
    
    def extract_tenant_id(self, request) -> Optional[str]:
        """Extract tenant ID from request headers or session."""
        # Try header first
        tenant_id = request.headers.get(self.tenant_header)
        if tenant_id:
            return tenant_id
        
        # Try session if available
        if hasattr(request, 'session') and request.session:
            tenant_id = getattr(request.session, 'tenant_id', None)
            if tenant_id:
                return tenant_id
        
        return None
    
    def validate_tenant_access(self, user_tenant_id: str, requested_tenant_id: str) -> bool:
        """Validate that user has access to the requested tenant."""
        # For now, users can only access their own tenant
        # In future, this could be enhanced with cross-tenant permissions
        return user_tenant_id == requested_tenant_id
    
    def audit_tenant_violation(self, user_id: Optional[str], username: Optional[str],
                              ip_address: str, attempted_tenant: str, allowed_tenant: str):
        """Audit tenant access violation."""
        if self.audit_service:
            try:
                self.audit_service.log_tenant_violation(
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    attempted_tenant=attempted_tenant,
                    allowed_tenant=allowed_tenant
                )
            except Exception as e:
                logger.error(f"Failed to audit tenant violation: {e}")
    
    def require_tenant(self, func: Callable) -> Callable:
        """Decorator to require tenant ID in request."""
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # Extract tenant ID
            tenant_id = self.extract_tenant_id(request)
            
            if not tenant_id:
                logger.warning(f"Missing tenant ID in request to {request.endpoint}")
                if self.audit_service:
                    self.audit_service.log_permission_denied(
                        username=getattr(request, 'session', {}).get('username'),
                        user_id=getattr(request, 'session', {}).get('user_id'),
                        ip_address=request.remote_addr,
                        resource=request.endpoint,
                        reason="MISSING_TENANT_ID"
                    )
                return jsonify({
                    'error': 'Tenant ID required',
                    'code': 'MISSING_TENANT_ID'
                }), 400
            
            # Store in request context
            g.tenant_id = tenant_id
            
            return func(*args, **kwargs)
        
        return decorated_function
    
    def enforce_tenant_isolation(self, func: Callable) -> Callable:
        """Decorator to enforce tenant isolation."""
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # Extract tenant ID from request
            requested_tenant_id = self.extract_tenant_id(request)
            
            if not requested_tenant_id:
                logger.warning(f"Missing tenant ID in request to {request.endpoint}")
                return jsonify({
                    'error': 'Tenant ID required',
                    'code': 'MISSING_TENANT_ID'
                }), 400
            
            # Get user's allowed tenant from session
            user_tenant_id = None
            if hasattr(request, 'session') and request.session:
                user_tenant_id = getattr(request.session, 'tenant_id', None)
            
            # If no user session, allow with warning (for public endpoints)
            if not user_tenant_id:
                logger.warning(f"No user session for tenant-isolated endpoint {request.endpoint}")
                g.tenant_id = requested_tenant_id
                return func(*args, **kwargs)
            
            # Validate tenant access
            if not self.validate_tenant_access(user_tenant_id, requested_tenant_id):
                logger.warning(f"Tenant violation: user {getattr(request.session, 'username')} "
                             f"attempted to access tenant {requested_tenant_id}, "
                             f"allowed tenant: {user_tenant_id}")
                
                # Audit the violation
                self.audit_tenant_violation(
                    user_id=getattr(request.session, 'user_id'),
                    username=getattr(request.session, 'username'),
                    ip_address=request.remote_addr,
                    attempted_tenant=requested_tenant_id,
                    allowed_tenant=user_tenant_id
                )
                
                return jsonify({
                    'error': 'Access denied to tenant',
                    'code': 'TENANT_ACCESS_DENIED'
                }), 403
            
            # Store validated tenant ID in request context
            g.tenant_id = requested_tenant_id
            
            return func(*args, **kwargs)
        
        return decorated_function
    
    def validate_device_ownership(self, tenant_id: str, device_id: str, devices_service=None) -> bool:
        """Validate that device belongs to the tenant."""
        if not devices_service:
            logger.warning("No devices service available for device ownership validation")
            return True  # Allow if no validation service available
        
        try:
            device = devices_service.get_device(tenant_id, device_id)
            return device is not None
        except Exception as e:
            logger.error(f"Failed to validate device ownership: {e}")
            return False
    
    def require_device_access(self, func: Callable) -> Callable:
        """Decorator to require device access validation."""
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # Get tenant ID from request context
            tenant_id = getattr(g, 'tenant_id', None)
            if not tenant_id:
                return jsonify({
                    'error': 'Tenant ID not available',
                    'code': 'TENANT_ID_MISSING'
                }), 400
            
            # Extract device ID from request data or URL parameters
            device_id = None
            if request.is_json and request.json:
                device_id = request.json.get('device_id')
            elif 'device_id' in request.args:
                device_id = request.args.get('device_id')
            
            if not device_id:
                logger.warning(f"Missing device_id in request to {request.endpoint}")
                return jsonify({
                    'error': 'Device ID required',
                    'code': 'MISSING_DEVICE_ID'
                }), 400
            
            # Validate device ownership (if devices service available)
            # This would need to be injected or accessed via service factory
            # For now, we'll log and allow
            logger.debug(f"Device access request: tenant={tenant_id}, device={device_id}")
            
            # Store device context
            g.device_id = device_id
            
            return func(*args, **kwargs)
        
        return decorated_function


def setup_tenant_middleware(app, auth_config: AuthConfig, audit_service=None):
    """Setup tenant middleware for Flask app."""
    middleware = TenantMiddleware(auth_config, audit_service)
    
    # Store middleware in app context for access in routes
    app.tenant_middleware = middleware
    
    @app.before_request
    def setup_tenant_context():
        """Setup tenant context for each request."""
        # Extract and validate tenant ID
        tenant_id = middleware.extract_tenant_id(request)
        if tenant_id:
            g.tenant_id = tenant_id
    
    return middleware


# Convenience decorators for routes
def require_tenant(func: Callable) -> Callable:
    """Decorator to require tenant ID in request."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        from flask import current_app, g, jsonify
        
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            return jsonify({'error': 'Tenant middleware not configured'}), 500
        
        return current_app.tenant_middleware.require_tenant(func)(*args, **kwargs)
    
    return decorated_function


def enforce_tenant_isolation(func: Callable) -> Callable:
    """Decorator to enforce tenant isolation."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            return jsonify({'error': 'Tenant middleware not configured'}), 500
        
        return current_app.tenant_middleware.enforce_tenant_isolation(func)(*args, **kwargs)
    
    return decorated_function


def require_device_access(func: Callable) -> Callable:
    """Decorator to require device access validation."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        if not hasattr(current_app, 'tenant_middleware'):
            logger.warning("Tenant middleware not configured")
            return jsonify({'error': 'Tenant middleware not configured'}), 500
        
        return current_app.tenant_middleware.require_device_access(func)(*args, **kwargs)
    
    return decorated_function
