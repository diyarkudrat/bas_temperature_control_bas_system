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

import requests

from flask import Flask, jsonify, request

from app_platform.config.auth import AuthConfig
from app_platform.config.config import ServerConfig, get_server_config
from app_platform.config.rate_limit import AtomicRateLimitConfig
from app_platform.utils.circuit_breaker import CircuitBreaker
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

from apps.auth_service.services import (
    Auth0ManagementClient,
    EmailVerificationService,
    InviteService,
    ProvisioningTokenService,
    ServiceConfigurationError,
)

logger = get_structured_logger("auth.main")
service_token_logger = get_structured_logger("auth.service_tokens")


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
    http_session: Optional[requests.Session] = None
    provisioning_service: Optional[ProvisioningTokenService] = None
    invite_service: Optional[InviteService] = None
    verification_service: Optional[EmailVerificationService] = None
    auth0_mgmt_client: Optional[Auth0ManagementClient] = None


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
        service_token_logger.error(
            "Failed to load service JWT keyset",
            extra={"prefix": prefix},
            exc_info=True,
        )
        raise RuntimeError("Service JWT keyset configuration invalid") from exc

    replay_cache = load_replay_cache_from_env(prefix=prefix, namespace="auth-service")
    cache_backend = "redis" if getattr(replay_cache, "_redis", None) else "in-process"
    service_token_logger.info(
        "Replay cache initialized",
        extra={"prefix": prefix, "backend": cache_backend},
    )

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
    service_token_logger.info(
        "Service JWT verifier configured",
        extra={
            "prefix": prefix,
            "kid_count": len(kids),
            "default_kid": keyset.default_kid,
            "audience": expected_audience,
            "issuer": expected_issuer,
            "required_scopes": required_scopes,
            "allowed_subjects": allowed_subjects,
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

    app.config.setdefault("ORG_SIGNUP_V2_ENABLED", auth_config.org_signup_v2_enabled)
    app.config.setdefault("DEVICE_RBAC_ENFORCEMENT", auth_config.device_rbac_enforcement)

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

    http_session = requests.Session()
    http_session.headers.update({"User-Agent": "bas-auth-service/1.0"})

    breaker_cfg = server_config.breaker
    mgmt_breaker = CircuitBreaker(
        failure_threshold=getattr(breaker_cfg, "failure_threshold", 5),
        window_seconds=getattr(breaker_cfg, "window_seconds", 30),
        half_open_after_s=getattr(breaker_cfg, "half_open_after_seconds", 15),
    )

    auth0_client: Optional[Auth0ManagementClient] = None
    try:
        auth0_client = Auth0ManagementClient(server_config.auth0_mgmt, http_session, breaker=mgmt_breaker)
        if not auth0_client.enabled:
            auth0_client = None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Auth0 management client initialization failed: %s", exc)
        auth0_client = None

    provisioning_service: Optional[ProvisioningTokenService] = None
    if auth_config.org_signup_v2_enabled:
        try:
            provisioning_service = ProvisioningTokenService(auth_config)
        except ServiceConfigurationError as exc:
            logger.error("Provisioning service initialization failed: %s", exc)
            provisioning_service = None

    invite_service: Optional[InviteService] = None
    if auth_config.org_signup_v2_enabled:
        invite_service = InviteService(
            config=auth_config,
            firestore_factory=firestore_factory,
            auth0_client=auth0_client,
        )

    verification_service: Optional[EmailVerificationService] = None
    if service_tokens is not None:
        api_base_url = os.getenv("API_SERVICE_URL") or os.getenv("ORG_API_BASE_URL") or "http://localhost:8080"
        events_replay = load_replay_cache_from_env(
            prefix="AUTH_EVENTS",
            namespace="auth-email-events",
            default_ttl_seconds=getattr(auth_config, "replay_cache_ttl_seconds", 120) or 120,
            default_max_entries=2048,
        )
        try:
            verification_service = EmailVerificationService(
                api_base_url=api_base_url,
                http_client=http_session,
                replay_cache=events_replay,
                signing_keyset=service_tokens.keyset,
                signing_subject="auth.events.email_verified",
                signing_audience=service_tokens.audience,
                signing_issuer=service_tokens.issuer,
                signing_scopes=service_tokens.required_scopes,
                request_timeout_s=float(os.getenv("AUTH_EVENTS_TIMEOUT_S", "5")),
                ttl_seconds=min(getattr(auth_config, "provisioning_jwt_ttl_seconds", 60), 60),
                webhook_secret=getattr(auth_config, "auth0_webhook_secret", None),
            )
        except ServiceConfigurationError as exc:
            logger.error("Verification service initialization failed: %s", exc)
            verification_service = None

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
        http_session=http_session,
        provisioning_service=provisioning_service,
        invite_service=invite_service,
        verification_service=verification_service,
        auth0_mgmt_client=auth0_client,
    )

    app.config.setdefault("AUTH_SERVICE_RUNTIME", runtime)
    app.config.setdefault("rate_limit_holder", rate_limit_holder)
    if service_tokens is not None:
        app.config.setdefault("SERVICE_TOKENS", service_tokens)

    logger.info(
        "Auth service runtime initialized",
        extra={
            "auth_enabled": bool(auth_config.auth_enabled),
            "firestore_enabled": bool(firestore_factory),
            "db_path": db_path,
            "service_tokens_enabled": service_tokens is not None,
            "rate_limit_per_ip": getattr(auth_config, "rate_limit_per_ip", None),
            "org_signup_v2": auth_config.org_signup_v2_enabled,
            "device_rbac_enforcement": auth_config.device_rbac_enforcement,
        },
    )

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
        if runtime.provisioning_service is not None:
            request.provisioning_service = runtime.provisioning_service
        if runtime.invite_service is not None:
            request.invite_service = runtime.invite_service
        if runtime.verification_service is not None:
            request.verification_service = runtime.verification_service
        if runtime.auth0_mgmt_client is not None:
            request.auth0_mgmt_client = runtime.auth0_mgmt_client
        logger.debug(
            "Request context hydrated",
            extra={
                "firestore_attached": runtime.firestore_factory is not None,
                "service_tokens_attached": runtime.service_tokens is not None,
                "provisioning_attached": runtime.provisioning_service is not None,
                "invite_service_attached": runtime.invite_service is not None,
                "auth0_mgmt_attached": runtime.auth0_mgmt_client is not None,
            },
        )


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

