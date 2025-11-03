"""Health endpoints."""

from __future__ import annotations

import time

from flask import Blueprint, current_app, jsonify, request

from logging_lib import get_logger as get_structured_logger

from apps.api.http import routes as http_routes


health_bp = Blueprint("health", __name__)

logger = get_structured_logger("api.http.health")


@health_bp.route("/api/health")
def health():
    """Check the health of the API."""

    firestore_factory = current_app.config.get("firestore_factory")

    logger.debug(
        "Health route invoked",
        extra={"firestore_enabled": firestore_factory is not None},
    )

    return http_routes.health(request.auth_config, firestore_factory)


@health_bp.route("/api/health/auth")
def auth_health():
    """Check the health of the auth service."""

    logger.debug("Auth health route invoked")

    return http_routes.auth_health(request.auth_provider)


@health_bp.route("/healthz")
def healthz():
    """Liveness probe."""

    return (jsonify({"status": "ok", "timestamp": time.time()}), 200)


@health_bp.route("/readyz")
def readyz():
    """Readiness probe that verifies dependent services."""

    firestore_factory = current_app.config.get("firestore_factory")
    auth_provider = getattr(request, "auth_provider", None)

    issues = []

    if firestore_factory:
        try:
            firestore_status = firestore_factory.health_check()

            if firestore_status.get("status") != "healthy":
                issues.append("firestore")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Firestore readiness check failed", exc_info=True)
            issues.append("firestore:" + str(exc))

    if auth_provider is not None:
        try:
            provider_status = auth_provider.healthcheck()

            if provider_status.get("status") not in {"ok", "healthy"}:
                issues.append("auth_provider")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Auth provider readiness check failed", exc_info=True)

            issues.append("auth_provider:" + str(exc))

    status_code = 200 if not issues else 503
    payload = {
        "status": "ready" if not issues else "degraded",
        "issues": issues,
        "timestamp": time.time(),
    }
    response = jsonify(payload)
    response.status_code = status_code

    return response