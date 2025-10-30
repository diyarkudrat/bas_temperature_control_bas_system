#!/usr/bin/env python3
"""
BAS Server — Flask composition root for BAS (building automation system).

Responsibilities:
- Wire controller, auth runtime, and optional Firestore + tenant middleware
- Register HTTP routes, security headers, and API versioning headers
- Provide request lifecycle hooks and lightweight metrics
- Keep orchestration/DI here; business logic in application/auth/ and application/hardware/; HTTP handlers in apps/api/http/

Notes:
- Auth provider is built at import for fast /api/health/auth
- Firestore is optional and health-checked before use
"""

import time
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import os as _os
import os
from typing import Optional, Callable

from logging_lib import configure as configure_structured_logging, get_logger as get_structured_logger
from logging_lib.flask_ext import register_flask_context

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# Authentication imports
from app_platform.config.auth import AuthConfig
from apps.api.http.middleware import add_security_headers as _sec_headers

from apps.api.http.versioning import build_versioning_applier
from app_platform.errors.api import register_error_handlers
from apps.api.bootstrap import load_server_config, build_auth_runtime, build_firestore_factory, build_tenant_middleware
from app_platform.observability.metrics import AuthMetrics
from adapters.providers.mock_auth0 import MockAuth0Provider
from adapters.providers.base import AuthProvider
from adapters.providers.factory import build_auth0_provider
from adapters.providers.deny_all import DenyAllAuthProvider
from application.hardware.bas_hardware_controller import BASController
from app_platform.config.rate_limit import AtomicRateLimitConfig
from apps.api.http.router import register_routes
from apps.api.clients import AuthServiceClient, AuthServiceClientConfig

# Configure logging early to ensure consistent format/level
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
configure_structured_logging(service="api", env=os.getenv("BAS_ENV", "local"))
get_structured_logger("api.bootstrap").info("api service starting")

# Use local templates directory to avoid legacy coupling
_TEMPLATE_DIR = os.path.normpath(os.path.join(_THIS_DIR, 'templates'))
app = Flask(__name__, template_folder=_TEMPLATE_DIR)
CORS(app)
register_flask_context(app, service="api")

# Default versioning applier; replaced during setup if build succeeds
_apply_versioning = lambda resp: resp

# ------------------------- Global singletons -------------------------
controller = BASController()
server_config = load_server_config()
app.config["controller"] = controller

# Authentication singletons (populated in init_auth)
auth_config: Optional[AuthConfig] = None
auth_provider: Optional[AuthProvider] = None
auth_metrics: Optional[AuthMetrics] = None
auth_service_client_factory: Optional[Callable[[], AuthServiceClient]] = None
_rate_limit_holder = AtomicRateLimitConfig(server_config.rate_limit)
app.config["rate_limit_holder"] = _rate_limit_holder


def _build_auth_provider(cfg) -> AuthProvider:
    """Create the authentication provider based on server configuration."""

    try:
        provider_kind = (cfg.auth_provider or "mock").lower()

        if provider_kind == "auth0":
            # Strict env validation: issuer must be https and audience provided
            domain = (cfg.auth0_domain or "").strip()
            audience = (cfg.auth0_audience or "").strip()

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
            if not cfg.use_emulators:
                logger.error("Mock auth provider is not allowed without emulators enabled")

                return DenyAllAuthProvider()

            issuer = f"https://{cfg.auth0_domain}/" if cfg.auth0_domain else "https://mock.auth0/"

            return MockAuth0Provider(
                audience=str(cfg.auth0_audience or "bas-api"),
                issuer=issuer,
            )
            
        logger.warning("Unknown AUTH_PROVIDER '%s'; using deny-all auth provider", provider_kind)

        return DenyAllAuthProvider()
    except Exception as e:
        logger.error("Auth provider initialization failed: %s", e)

        return DenyAllAuthProvider()


def _build_auth_runtime(cfg):
    """Compose DI-friendly auth runtime components."""

    provider = _build_auth_provider(cfg)
    metrics = AuthMetrics()

    return provider, metrics


# Initialize provider/metrics at import so /api/health/auth is responsive early
auth_provider, auth_metrics = build_auth_runtime(server_config)

# Firestore/tenant globals
firestore_factory = None
tenant_middleware = None

def init_auth():
    """Initialize authentication system."""

    global auth_config
    global firestore_factory, tenant_middleware
    global auth_service_client_factory

    try:
        logger.info("Initializing authentication system")

        # Load auth configuration (shared invariants with auth service)
        auth_config = AuthConfig.from_file('configs/app/auth_config.json')
        if not auth_config.validate():
            logger.error("Invalid auth configuration")
            return False

        # Initialize Firestore if enabled for tenant middleware or other features
        if any([auth_config.use_firestore_telemetry, auth_config.use_firestore_auth, auth_config.use_firestore_audit]):
            logger.info("Initializing Firestore services")
            firestore_factory = build_firestore_factory(server_config)

            # Health check
            health = firestore_factory.health_check()
            if health['status'] != 'healthy':
                logger.error(f"Firestore health check failed: {health}")
                return False

            logger.info("Firestore services initialized successfully")

        # Initialize tenant middleware if Firestore is enabled
        if firestore_factory:
            tenant_middleware = build_tenant_middleware(auth_config, firestore_factory)
            logger.info("Tenant middleware initialized")

        # Auth service client factory keeps shared IO out of blueprints
        cfg = AuthServiceClientConfig.from_env(os.environ)

        def _client_factory() -> AuthServiceClient:
            return AuthServiceClient(cfg)

        auth_service_client_factory = _client_factory
        app.config["auth_service_client_factory"] = _client_factory

        # Update app config with Firestore factory for handlers
        app.config["firestore_factory"] = firestore_factory
        logger.info("Authentication system initialized successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to initialize auth system: {e}")
        return False

# routes are registered via blueprints; see apps.api.http.router.register_routes

# Add request context setup
# ---------------------- Request lifecycle hooks ----------------------
@app.before_request
def setup_auth_context():
    """Setup authentication context for each request."""

    # Always attach server_config for downstream components
    request.server_config = server_config

    # Attach rate limit snapshot for per-user dynamic limits (hot-reloaded)
    try:
        request.rate_limit_snapshot = _rate_limit_holder.get_snapshot()
    except Exception:
        request.rate_limit_snapshot = getattr(server_config, 'rate_limit', None)

    # Attach auth provider for routes and middleware
    request.auth_provider = auth_provider

    # Attach lightweight metrics aggregator
    try:
        request.auth_metrics = auth_metrics
    except Exception:
        pass

    if auth_config:
        request.auth_config = auth_config

    if auth_service_client_factory:
        try:
            request.auth_service_client = auth_service_client_factory()
        except Exception:
            logger.warning("Failed to create auth service client", exc_info=True)

    # Initialize tenant context if middleware is available
    if tenant_middleware and auth_config:
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
register_routes(app)

## Versioned blueprints removed; unversioned routes carry v2 semantics via headers

if __name__ == '__main__':
    # Initialize authentication system
    if not init_auth():
        logger.warning("Authentication system initialization failed - running without auth")
    
    # No cleanup thread needed
    
    port = int(_os.getenv('PORT', '8080'))
    logger.info("Starting BAS Server...")
    logger.info(f"Dashboard available at: http://localhost:{port}")
    logger.info(f"API available at: http://localhost:{port}/api/")
    if auth_config and auth_config.auth_enabled:
        logger.info("Authentication system enabled")
        logger.info(f"Auth endpoints available at: http://localhost:{port}/auth/")
    
    app.run(host='0.0.0.0', port=port, debug=False)


