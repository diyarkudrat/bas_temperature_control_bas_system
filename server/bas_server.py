#!/usr/bin/env python3
"""
BAS Server - Flask application wiring for BAS (building automation system).

This module composes:
- Controller (hardware logic)
- Auth (config, sessions, audit, provider)
- Firestore service factory (optional)
- HTTP routes and versioning headers

Focus: keep orchestration and request hooks here; move logic to services.
"""

import json
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, g
from flask_cors import CORS
import logging
import os as _os
from typing import Optional

# Authentication imports
from auth import (
    AuthConfig, UserManager, SessionManager,
    AuditLogger, RateLimiter,
    require_auth, add_security_headers as _sec_headers
)

# Firestore imports
from services.firestore.service_factory import build_service_factory_with_config
from http.versioning import build_versioning_applier
from http import routes as http_routes
from errors import register_error_handlers
from auth.tenant_middleware import TenantMiddleware
from config.config import get_server_config
from auth.metrics import AuthMetrics
from auth.providers import MockAuth0Provider, AuthProvider, Auth0Provider, build_auth0_provider
from auth.providers.deny_all import DenyAllAuthProvider
from services.bas_hardware_controller import BASController

# Configure logging early to ensure consistent format/level
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Default versioning applier; replaced during setup if build succeeds
_apply_versioning = lambda resp: resp

# ------------------------- Global singletons -------------------------
controller = BASController()
server_config = get_server_config()

# Authentication singletons (populated in init_auth)
auth_config = None
user_manager = None
session_manager = None
audit_logger = None
rate_limiter = None
auth_provider: Optional[AuthProvider] = None
auth_metrics = AuthMetrics()


def _build_auth_provider_from_env() -> AuthProvider:
    """Create the authentication provider based on server configuration.

    Phase 1:
    - auth0: uses JWKS with strict validation
    - mock: allowed only with emulators enabled; otherwise deny-all
    - unknown or invalid config: deny-all
    """
    try:
        provider_kind = (server_config.auth_provider or "mock").lower()
        if provider_kind == "auth0":
            # Strict env validation: issuer must be https and audience provided
            domain = (server_config.auth0_domain or "").strip()
            audience = (server_config.auth0_audience or "").strip()
            if not domain or not audience:
                raise ValueError("AUTH0_DOMAIN and AUTH0_AUDIENCE are required for auth0 provider")
            issuer = f"https://{domain}/" if not domain.startswith("https://") else domain
            provider = build_auth0_provider({
                "issuer": issuer,
                "audience": audience,
            })
            return provider
        if provider_kind == "mock":
            # Disallow mock in prod unless emulators explicitly enabled
            if not server_config.use_emulators:
                logger.error("Mock auth provider is not allowed without emulators enabled")
                return DenyAllAuthProvider()
            issuer = f"https://{server_config.auth0_domain}/" if server_config.auth0_domain else "https://mock.auth0/"
            return MockAuth0Provider(
                audience=str(server_config.auth0_audience or "bas-api"),
                issuer=issuer,
            )
        logger.warning("Unknown AUTH_PROVIDER '%s'; using deny-all auth provider", provider_kind)
        return DenyAllAuthProvider()
    except Exception as e:
        logger.error("Auth provider initialization failed: %s", e)
        return DenyAllAuthProvider()


## DenyAllAuthProvider moved to auth.providers.deny_all


# Initialize provider at import so /api/health/auth is responsive early
auth_provider = _build_auth_provider_from_env()

# Firestore global variables
firestore_factory = None
tenant_middleware = None

def init_auth():
    """Initialize authentication system."""
    global auth_config, user_manager, session_manager
    global audit_logger, rate_limiter
    global firestore_factory, tenant_middleware
    
    try:
        logger.info("Initializing authentication system")
        
        # Load auth configuration
        auth_config = AuthConfig.from_file('config/auth_config.json')
        if not auth_config.validate():
            logger.error("Invalid auth configuration")
            return False
        
        # Initialize Firestore if enabled
        if any([auth_config.use_firestore_telemetry, auth_config.use_firestore_auth, auth_config.use_firestore_audit]):
            logger.info("Initializing Firestore services")
            # Manual composition root: construct factory with config
            firestore_factory = build_service_factory_with_config(auth_config)
            
            # Health check
            health = firestore_factory.health_check()
            if health['status'] != 'healthy':
                logger.error(f"Firestore health check failed: {health}")
                return False
            
            logger.info("Firestore services initialized successfully")
        
        # Initialize tenant middleware if Firestore is enabled
        if firestore_factory:
            tenant_middleware = TenantMiddleware(auth_config, firestore_factory)
            logger.info("Tenant middleware initialized")
        
        # Initialize managers (will use Firestore if enabled)
        # Use an ephemeral sqlite database file path when Firestore features are disabled.
        db_path = 'bas.sqlite3'
        user_manager = UserManager(db_path, auth_config, firestore_factory)
        session_manager = SessionManager(db_path, auth_config, firestore_factory)
        
        # Initialize services
        audit_logger = AuditLogger(db_path, firestore_factory)
        rate_limiter = RateLimiter(auth_config)
        
        logger.info("Authentication system initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize auth system: {e}")
        return False

@app.route('/')
def dashboard():
    return http_routes.dashboard()

@app.route('/auth/login')
def auth_login_page():
    return http_routes.auth_login_page()


@app.route('/api/health')
def health():
    return http_routes.health(auth_config, firestore_factory)

@app.route('/api/health/auth')
def auth_health():
    return http_routes.auth_health(auth_provider)

@app.route('/api/sensor_data', methods=['POST'])
def receive_sensor_data():
    return http_routes.receive_sensor_data(controller, firestore_factory)

@app.route('/api/status')
def get_status():
    return http_routes.get_status(controller)

@app.route('/api/set_setpoint', methods=['POST'])
@require_auth(required_role="operator")
def set_setpoint():
    return http_routes.set_setpoint(controller)

@app.route('/api/telemetry')
@require_auth(required_role="read-only")
def get_telemetry():
    return http_routes.get_telemetry(firestore_factory)

@app.route('/api/config')
def get_config():
    return http_routes.get_config(controller)

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Authenticate user with username/password."""
    if not auth_config or not auth_config.auth_enabled:
        logger.warning("Authentication attempt while auth disabled")
        return jsonify({"error": "Authentication disabled"}), 503
    
    try:
        logger.info("Authentication login attempt")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            logger.warning("Missing required fields in login request")
            return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400
        
        # Rate limiting check
        allowed, message = rate_limiter.is_allowed(request.remote_addr, username)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {username} from {request.remote_addr}")
            audit_logger.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429
        
        # User authentication
        user = user_manager.authenticate_user(username, password)
        if not user:
            logger.warning(f"Authentication failed for {username} from {request.remote_addr}")
            rate_limiter.record_attempt(request.remote_addr, username)
            audit_logger.log_auth_failure(username, request.remote_addr, "INVALID_CREDENTIALS")
            return jsonify({"error": "Invalid credentials", "code": "AUTH_FAILED"}), 401
        
        # Check if account is locked
        if user.is_locked():
            logger.warning(f"Login attempt on locked account: {username}")
            audit_logger.log_auth_failure(username, request.remote_addr, "ACCOUNT_LOCKED")
            return jsonify({"error": "Account locked", "code": "USER_LOCKED"}), 423
        
        # Create session directly
        logger.info(f"Creating session for {username}")
        
        # Create session
        session = session_manager.create_session(username, user.role, request)
        
        # Update user login time
        user_manager.update_last_login(username)
        
        # Clear rate limiting for successful auth
        rate_limiter.clear_attempts(request.remote_addr, username)
        
        # Audit log
        audit_logger.log_auth_success(username, request.remote_addr, session.session_id)
        
        logger.info(f"Authentication successful for {username}")
        
        # Create response with httpOnly cookie
        response = jsonify({
            "status": "success",
            "expires_in": auth_config.session_timeout,
            "user": {"username": username, "role": user.role}
        })
        
        # Set httpOnly cookie for session
        response.set_cookie(
            'bas_session_id', 
            session.session_id, 
            max_age=auth_config.session_timeout,
            httponly=True,
            secure=True,  # Only over HTTPS in production
            samesite='Strict'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in auth login: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    """Terminate user session."""
    try:
        logger.info("Logout request")
        
        # Get session ID from cookie or request body
        session_id = request.cookies.get('bas_session_id')
        if not session_id:
            data = request.get_json() or {}
            session_id = data.get('session_id')
        
        if session_id:
            if session_manager is not None:
                session_manager.invalidate_session(session_id)
            if audit_logger is not None:
                audit_logger.log_session_destruction(session_id)
            logger.info(f"Session invalidated: {session_id[:12]}...")
        
        # Create response and clear cookie
        response = jsonify({"status": "success", "message": "Logged out successfully"})
        response.set_cookie('bas_session_id', '', max_age=0, httponly=True, secure=True, samesite='Strict')
        
        return response
        
    except Exception as e:
        logger.error(f"Error in auth logout: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth/status')
def auth_status():
    """Check session validity and get user info."""
    session_id = request.cookies.get('bas_session_id') or request.headers.get('X-Session-ID')
    
    if not session_id:
        logger.warning("Auth status check without session ID")
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400
    
    session = session_manager.validate_session(session_id, request)
    if not session:
        logger.warning(f"Invalid session in status check: {session_id[:12]}...")
        return jsonify({"error": "Invalid or expired session", "code": "SESSION_INVALID"}), 401
    
    logger.debug(f"Session status check successful for {session.username}")
    return jsonify({
        "status": "valid",
        "user": {
            "username": session.username,
            "role": session.role,
            "login_time": session.created_at
        },
        "expires_in": int(session.expires_at - time.time())
    })

# Add request context setup
# ---------------------- Request lifecycle hooks ----------------------
@app.before_request
def setup_auth_context():
    """Setup authentication context for each request."""
    # Always attach server_config for downstream components
    request.server_config = server_config
    # Attach auth provider for routes and middleware
    request.auth_provider = auth_provider
    # Attach lightweight metrics aggregator
    try:
        request.auth_metrics = auth_metrics
    except Exception:
        pass
    if auth_config:
        request.auth_config = auth_config
        request.session_manager = session_manager
        request.audit_logger = audit_logger
        
        # Initialize tenant context if middleware is available
        if tenant_middleware:
            tenant_middleware.setup_tenant_context(request)

    # Apply security + versioning headers: build once, safely
    global _apply_versioning
    try:
        _apply_versioning = build_versioning_applier(
            sunset_v1_http_date=_os.getenv('SERVER_V1_SUNSET'),
            deprecate_v1=_os.getenv('SERVER_V1_DEPRECATE', 'true').lower() in {'1', 'true', 'yes'},
        )
    except Exception:
        # placeholder for metrics
        _apply_versioning = (lambda resp: resp)

@app.after_request
def _after(resp):
    try:
        resp = _sec_headers(resp)
    except Exception:
        # placeholder for metrics
        pass
    try:
        resp = _apply_versioning(resp)
    except Exception:
        # placeholder for metrics
        pass
    return resp

register_error_handlers(app)

## Versioned blueprints removed; unversioned routes carry v2 semantics via headers

if __name__ == '__main__':
    # Initialize authentication system
    if not init_auth():
        logger.warning("Authentication system initialization failed - running without auth")
    
    # No cleanup thread needed
    
    logger.info("Starting BAS Server...")
    logger.info("Dashboard available at: http://localhost:8080")
    logger.info("API available at: http://localhost:8080/api/")
    if auth_config and auth_config.auth_enabled:
        logger.info("Authentication system enabled")
        logger.info("Auth endpoints available at: http://localhost:8080/auth/")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
