"""Health endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app, request

from logging_lib import get_logger as get_structured_logger

from apps.api.http import routes as http_routes


health_bp = Blueprint("health", __name__)

logger = get_structured_logger("api.http.health")


@health_bp.route("/api/health")
def health():
    firestore_factory = current_app.config.get("firestore_factory")
    logger.debug(
        "Health route invoked",
        extra={"firestore_enabled": firestore_factory is not None},
    )
    return http_routes.health(request.auth_config, firestore_factory)


@health_bp.route("/api/health/auth")
def auth_health():
    logger.debug("Auth health route invoked")
    return http_routes.auth_health(request.auth_provider)


