"""Health endpoints."""

from __future__ import annotations

from flask import Blueprint, request, current_app

from apps.api.http import routes as http_routes


health_bp = Blueprint("health", __name__)


@health_bp.route("/api/health")
def health():
    firestore_factory = current_app.config.get("firestore_factory")
    return http_routes.health(request.auth_config, firestore_factory)


@health_bp.route("/api/health/auth")
def auth_health():
    return http_routes.auth_health(request.auth_provider)


