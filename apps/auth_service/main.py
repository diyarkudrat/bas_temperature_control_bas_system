"""Authentication service composition root.

This module bootstraps the standalone authentication service while reusing the
pure domain models that previously lived inside the monolithic API application.
Persistence, network clients, and other side effects remain wired inside this
service so cross-service coupling stays constrained to the shared data-model
layer.

Entry points:
    - :func:`create_app` constructs and wires a Flask application instance.
    - :func:`bootstrap_runtime` builds the underlying service dependencies.
    - :func:`register_healthcheck` exposes a lightweight readiness endpoint.

The remaining HTTP routes are registered lazily to avoid hard coupling to files
that will be introduced in subsequent patch-plan steps.  All runtime state is
carried inside the Flask application factory; no module-level singletons are
required, keeping the service safe to run inside Gunicorn or Cloud Run where
multiple worker processes import the module concurrently.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

from flask import Flask, jsonify, request

from app_platform.config.auth import AuthConfig
from app_platform.config.config import ServerConfig, get_server_config
from app_platform.config.rate_limit import AtomicRateLimitConfig
from application.auth.managers import SessionManager, UserManager
from application.auth.services import AuditLogger, RateLimiter
from logging_lib import configure as configure_structured_logging, get_logger as get_structured_logger
from logging_lib.flask_ext import register_flask_context

logger = logging.getLogger(__name__)


DEFAULT_CONFIG_PATH = os.getenv("AUTH_CONFIG_PATH", "configs/app/auth_config.json")
DEFAULT_DB_PATH = os.getenv("AUTH_SERVICE_DB_PATH", "bas.sqlite3")


@dataclass(slots=True)
class AuthRuntime:
    """Container for the auth service runtime dependencies."""

    config: AuthConfig
    server_config: ServerConfig
    rate_limit_holder: AtomicRateLimitConfig
    user_manager: UserManager
    session_manager: SessionManager
    audit_logger: AuditLogger
    rate_limiter: RateLimiter
    firestore_factory: Optional[Any] = None


def create_app(config_path: str | None = None) -> Flask:
    """Construct the auth Flask application.

    Parameters
    ----------
    config_path:
        Optional override for the auth configuration file location.
    """

    logging.basicConfig(level=logging.INFO)
    configure_structured_logging(service="auth", env=os.getenv("BAS_ENV", "local"))
    get_structured_logger("auth.bootstrap").info("auth service starting")
    logger.info("Creating auth service application")

    app = Flask(__name__)
    register_flask_context(app, service="auth")

    runtime = bootstrap_runtime(app, config_path=config_path)
    register_healthcheck(app, runtime)
    _register_request_hooks(app, runtime)
    _register_blueprints(app)

    return app


def bootstrap_runtime(app: Flask, *, config_path: str | None = None) -> AuthRuntime:
    """Initialize configuration and shared dependencies for the auth service."""

    cfg_path = config_path or DEFAULT_CONFIG_PATH
    auth_config = AuthConfig.from_file(cfg_path)
    auth_config.validate()

    server_config = get_server_config()

    firestore_factory = None
    if any([
        getattr(auth_config, "use_firestore_auth", False),
        getattr(auth_config, "use_firestore_audit", False),
        getattr(auth_config, "use_firestore_telemetry", False),
    ]):
        try:
            # Lazy import keeps Firestore optional for lightweight deployments.
            from apps.api.bootstrap import build_firestore_factory  # noqa: WPS433

            firestore_factory = build_firestore_factory(server_config)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Firestore factory initialization failed: %s", exc)
            firestore_factory = None

    db_path = os.getenv("AUTH_SERVICE_DB_PATH", DEFAULT_DB_PATH)

    rate_limit_holder = AtomicRateLimitConfig(server_config.rate_limit)

    user_manager = UserManager(db_path, auth_config, firestore_factory)
    session_manager = SessionManager(db_path, auth_config, firestore_factory)
    audit_logger = AuditLogger(db_path, firestore_factory)
    rate_limiter = RateLimiter(auth_config)

    runtime = AuthRuntime(
        config=auth_config,
        server_config=server_config,
        rate_limit_holder=rate_limit_holder,
        user_manager=user_manager,
        session_manager=session_manager,
        audit_logger=audit_logger,
        rate_limiter=rate_limiter,
        firestore_factory=firestore_factory,
    )

    app.config.setdefault("AUTH_SERVICE_RUNTIME", runtime)
    app.config.setdefault("rate_limit_holder", rate_limit_holder)

    logger.info("Auth service runtime initialized")

    return runtime


def register_healthcheck(app: Flask, runtime: AuthRuntime) -> None:
    """Expose a simple readiness endpoint for manual smoke testing."""

    @app.route("/healthz", methods=["GET"])
    def _healthcheck():  # pragma: no cover - exercised via manual smoke tests
        status = {
            "status": "ok",
            "auth_enabled": bool(runtime.config.auth_enabled),
            "firestore": "enabled" if runtime.firestore_factory else "disabled",
        }
        return jsonify(status), 200


def _register_request_hooks(app: Flask, runtime: AuthRuntime) -> None:
    """Attach request lifecycle hooks so blueprints can pull dependencies."""

    @app.before_request
    def _attach_runtime_to_request() -> None:
        request.auth_config = runtime.config
        request.server_config = runtime.server_config
        request.rate_limit_holder = runtime.rate_limit_holder
        request.session_manager = runtime.session_manager
        request.audit_logger = runtime.audit_logger
        request.rate_limiter = runtime.rate_limiter
        request.user_manager = runtime.user_manager
        if runtime.firestore_factory is not None:
            request.firestore_factory = runtime.firestore_factory


def _register_blueprints(app: Flask) -> None:
    """Register HTTP route blueprints if available."""

    try:
        from apps.auth_service.http.auth_routes import auth_bp  # noqa: WPS433
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("Auth routes not yet available: %s", exc)
        return

    app.register_blueprint(auth_bp)


def main() -> None:  # pragma: no cover - CLI entrypoint
    app = create_app()
    port = int(os.getenv("AUTH_SERVICE_PORT", "9090"))
    host = os.getenv("AUTH_SERVICE_HOST", "0.0.0.0")
    logger.info("Starting auth service on %s:%s", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()

