"""Controller/config endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app

from apps.api.http.middleware import require_auth
from apps.api.http import routes as http_routes


control_bp = Blueprint("control", __name__)


@control_bp.route("/api/sensor_data", methods=["POST"])
def receive_sensor_data():
    controller = current_app.config["controller"]
    firestore_factory = current_app.config.get("firestore_factory")
    return http_routes.receive_sensor_data(controller, firestore_factory)


@control_bp.route("/api/status")
@require_auth(required_role="read-only")
def get_status():
    controller = current_app.config["controller"]
    return http_routes.get_status(controller)


@control_bp.route("/api/set_setpoint", methods=["POST"])
@require_auth(required_role="operator")
def set_setpoint():
    controller = current_app.config["controller"]
    return http_routes.set_setpoint(controller)


@control_bp.route("/api/config")
@require_auth(required_role="read-only")
def get_config():
    controller = current_app.config["controller"]
    return http_routes.get_config(controller)


