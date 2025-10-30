"""Telemetry endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app

from logging_lib import get_logger as get_structured_logger

from apps.api.http.middleware import require_auth
from apps.api.http import routes as http_routes


telemetry_bp = Blueprint("telemetry", __name__)

logger = get_structured_logger("api.http.telemetry")


@telemetry_bp.route("/api/telemetry")
@require_auth(required_role="read-only")
def get_telemetry():
    firestore_factory = current_app.config.get("firestore_factory")
    logger.debug(
        "Telemetry route invoked",
        extra={"firestore_enabled": firestore_factory is not None},
    )
    return http_routes.get_telemetry(firestore_factory)


