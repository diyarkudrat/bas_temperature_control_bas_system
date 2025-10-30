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
from app_platform.security import (
    ReplayCache,
    ServiceKeySet,
    ServiceTokenError,
    load_replay_cache_from_env,
    load_service_keyset_from_env,
)
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
    service_tokens: Optional["ServiceTokenSettings"] = None


@dataclass(slots=True)
class ServiceTokenSettings:
    keyset: ServiceKeySet
    replay_cache: ReplayCache
    audience: Optional[str]
    issuer: Optional[str]
    allowed_subjects: tuple[str, ...]
    required_scopes: tuple[str, ...]


def _parse_csv(value: Optional[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    parts = [item.strip() for item in value.split(",")]
    return tuple(part for part in parts if part)


def _build_service_token_settings() -> ServiceTokenSettings:
    prefix = os.getenv("SERVICE_JWT_PREFIX", "SERVICE_JWT") or "SERVICE_JWT"

    try:
        keyset = load_service_keyset_from_env(prefix=prefix)
    except ServiceTokenError as exc:
        logger.error(
            "Failed to load service JWT keyset",
            extra={"prefix": prefix},
            exc_info=True,
        )
        raise RuntimeError("Service JWT keyset configuration invalid") from exc

    replay_cache = load_replay_cache_from_env(prefix=prefix, namespace="auth-service")

    auth0_domain = os.getenv("AUTH0_DOMAIN")
    expected_audience = (
        os.getenv("SERVICE_JWT_EXPECTED_AUDIENCE")
        or os.getenv("AUTH_SERVICE_TOKEN_AUDIENCE")
        or os.getenv("AUTH0_API_AUDIENCE")
        or "bas-auth"
    )

    issuer_env = os.getenv("SERVICE_JWT_EXPECTED_ISSUER") or os.getenv("AUTH_SERVICE_TOKEN_ISSUER")
    if issuer_env:
        expected_issuer = issuer_env
    elif auth0_domain:
        expected_issuer = f"https://{auth0_domain.strip().rstrip('/')}/"
    else:
        expected_issuer = "bas-api"

    allowed_subjects_env = os.getenv("SERVICE_JWT_ALLOWED_SUBJECTS")
    if allowed_subjects_env is None:
        default_subject = os.getenv("AUTH_SERVICE_TOKEN_SUBJECT", "api-backend")
        allowed_subjects = (default_subject,)
    else:
        allowed_subjects = _parse_csv(allowed_subjects_env)

    required_scopes_env = os.getenv("SERVICE_JWT_REQUIRED_SCOPES")
    if required_scopes_env is None:
        required_scopes = ("auth.limits.update",)
    else:
        required_scopes = _parse_csv(required_scopes_env)

    kids = [key.kid for key in keyset.keys()]
    logger.info(
        "Service JWT verifier configured",
        extra={
            "prefix": prefix,
            "kids": kids,
            "audience": expected_audience,
            "issuer": expected_issuer,
            "required_scopes": required_scopes,
        },
    )

    return ServiceTokenSettings(
        keyset=keyset,
        replay_cache=replay_cache,
        audience=expected_audience,
        issuer=expected_issuer,
        allowed_subjects=allowed_subjects,
        required_scopes=required_scopes,
    )


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

    service_tokens = _build_service_token_settings()

    runtime = AuthRuntime(
        config=auth_config,
        server_config=server_config,
        rate_limit_holder=rate_limit_holder,
        user_manager=user_manager,
        session_manager=session_manager,
        audit_logger=audit_logger,
        rate_limiter=rate_limiter,
        firestore_factory=firestore_factory,
        service_tokens=service_tokens,
    )

    app.config.setdefault("AUTH_SERVICE_RUNTIME", runtime)
    app.config.setdefault("rate_limit_holder", rate_limit_holder)
    if service_tokens is not None:
        app.config.setdefault("SERVICE_TOKENS", service_tokens)

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
        if runtime.service_tokens is not None:
            request.service_tokens = runtime.service_tokens


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

