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
from typing import Callable, Optional

import logging
import os
import os as _os
from flask import Flask, jsonify, request
from flask_cors import CORS

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
logger = get_structured_logger("api.main")
provider_logger = get_structured_logger("api.auth.provider")
firestore_logger = get_structured_logger("api.firestore")
client_logger = get_structured_logger("api.auth.client")
context_logger = get_structured_logger("api.context")
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
        provider_logger.info(
            "Selecting auth provider",
            extra={
                "provider_kind": provider_kind,
                "use_emulators": bool(cfg.use_emulators),
                "auth0_domain_present": bool(getattr(cfg, "auth0_domain", "")),
            },
        )

        if provider_kind == "auth0":
            # Strict env validation: issuer must be https and audience provided
            domain = (cfg.auth0_domain or "").strip()
            audience = (cfg.auth0_audience or "").strip()

            if not domain or not audience:
                provider_logger.error(
                    "Auth0 provider missing configuration",
                    extra={
                        "domain_present": bool(domain),
                        "audience_present": bool(audience),
                    },
                )
                raise ValueError("AUTH0_DOMAIN and AUTH0_AUDIENCE are required for auth0 provider")

            issuer = f"https://{domain}/" if not domain.startswith("https://") else domain

            provider = build_auth0_provider({
                "issuer": issuer,
                "audience": audience,
            })

            provider_logger.info(
                "Auth0 provider configured",
                extra={"issuer": issuer, "audience_length": len(audience)},
            )
            return provider

        if provider_kind == "mock":
            # Disallow mock in prod unless emulators explicitly enabled
            if not cfg.use_emulators:
                provider_logger.error("Mock auth provider is not allowed without emulators enabled")

                return DenyAllAuthProvider()

            issuer = f"https://{cfg.auth0_domain}/" if cfg.auth0_domain else "https://mock.auth0/"

            return MockAuth0Provider(
                audience=str(cfg.auth0_audience or "bas-api"),
                issuer=issuer,
            )
            
        provider_logger.warning(
            "Unknown auth provider configured; defaulting to deny-all",
            extra={"provider_kind": provider_kind},
        )

        return DenyAllAuthProvider()
    except Exception as e:
        provider_logger.exception("Auth provider initialization failed")

        return DenyAllAuthProvider()


def _build_auth_runtime(cfg):
    """Compose DI-friendly auth runtime components."""

    provider = _build_auth_provider(cfg)
    metrics = AuthMetrics()

    provider_logger.info(
        "Auth runtime constructed",
        extra={"provider_type": provider.__class__.__name__},
    )

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
            logger.error(
                "Invalid auth configuration",
                extra={
                    "auth_enabled": getattr(auth_config, "auth_enabled", None),
                    "session_timeout": getattr(auth_config, "session_timeout", None),
                },
            )
            return False

        logger.info(
            "Auth configuration loaded",
            extra={
                "auth_mode": getattr(auth_config, "auth_mode", None),
                "use_firestore": any([
                    auth_config.use_firestore_telemetry,
                    auth_config.use_firestore_auth,
                    auth_config.use_firestore_audit,
                ]),
            },
        )

        # Initialize Firestore if enabled for tenant middleware or other features
        if any([auth_config.use_firestore_telemetry, auth_config.use_firestore_auth, auth_config.use_firestore_audit]):
            firestore_logger.info("Initializing Firestore services")
            firestore_factory = build_firestore_factory(server_config)

            # Health check
            health = firestore_factory.health_check()
            if health['status'] != 'healthy':
                firestore_logger.error(
                    "Firestore health check failed",
                    extra={"health": health},
                )
                return False

            firestore_logger.info("Firestore services initialized successfully")

        # Initialize tenant middleware if Firestore is enabled
        if firestore_factory:
            tenant_middleware = build_tenant_middleware(auth_config, firestore_factory)
            firestore_logger.info("Tenant middleware initialized")

        # Auth service client factory keeps shared IO out of blueprints
        cfg = AuthServiceClientConfig.from_env(os.environ)
        client_logger.info(
            "Auth service client configuration loaded",
            extra={
                "audience": cfg.audience,
                "issuer": cfg.issuer,
                "ttl_seconds": cfg.token_ttl_seconds,
                "allowed_algorithms": cfg.allowed_algorithms,
            },
        )

        def _client_factory() -> AuthServiceClient:
            return AuthServiceClient(cfg)

        auth_service_client_factory = _client_factory
        app.config["auth_service_client_factory"] = _client_factory

        # Update app config with Firestore factory for handlers
        app.config["firestore_factory"] = firestore_factory
        logger.info(
            "Authentication system initialized successfully",
            extra={
                "firestore_enabled": firestore_factory is not None,
                "tenant_middleware_enabled": tenant_middleware is not None,
            },
        )
        return True

    except Exception:
        logger.exception("Failed to initialize auth system")
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
        context_logger.warning("Failed to capture rate limit snapshot", exc_info=True)
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
            client_logger.warning("Failed to create auth service client", exc_info=True)

    tenant_context = None
    if tenant_middleware and auth_config:
        try:
            tenant_middleware.setup_tenant_context(request)
            tenant_context = getattr(request, "_tenant_context", None)
            if tenant_context is not None:
                setattr(request, "tenant_context", tenant_context)
        except Exception:
            context_logger.warning("Tenant context setup failed", exc_info=True)

    # Apply security + versioning headers: build once, safely
    global _apply_versioning

    try:
        _apply_versioning = build_versioning_applier(
            sunset_v1_http_date=_os.getenv('SERVER_V1_SUNSET'),
            deprecate_v1=_os.getenv('SERVER_V1_DEPRECATE', 'true').lower() in {'1', 'true', 'yes'},
        )
    except Exception:
        context_logger.warning("Failed to build versioning applier", exc_info=True)
        _apply_versioning = (lambda resp: resp)

    context_logger.debug(
        "Request context hydrated",
        extra={
            "auth_config_attached": auth_config is not None,
            "auth_client_attached": hasattr(request, "auth_service_client"),
            "tenant_middleware": tenant_middleware is not None,
            "tenant_context": tenant_context.tenant_id if tenant_context else None,
        },
    )

@app.after_request
def _after(resp):
    try:
        resp = _sec_headers(resp)
    except Exception:
        context_logger.warning("Security headers application failed", exc_info=True)
        pass

    try:
        resp = _apply_versioning(resp)
    except Exception:
        context_logger.warning("Versioning header application failed", exc_info=True)
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
    logger.info("Starting BAS Server", extra={"port": port})
    logger.info("Dashboard available", extra={"url": f"http://localhost:{port}"})
    logger.info("API available", extra={"url": f"http://localhost:{port}/api/"})
    if auth_config and auth_config.auth_enabled:
        logger.info("Authentication system enabled", extra={"auth_enabled": True})
        logger.info("Auth endpoints available", extra={"url": f"http://localhost:{port}/auth/"})
    
    app.run(host='0.0.0.0', port=port, debug=False)


