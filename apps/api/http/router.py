"""Central route registration for the BAS API app.

Imports and registers all component blueprints so routes live in one place.
"""

from __future__ import annotations

from flask import Flask

from logging_lib import get_logger as get_structured_logger

from .ui_routes import ui_bp
from .health_routes import health_bp
from .control_routes import control_bp
from .telemetry_routes import telemetry_bp
from .auth_routes import auth_bp


def register_routes(app: Flask) -> None:
    logger = get_structured_logger("api.http.router")

    app.register_blueprint(ui_bp)
    logger.debug("Registered UI blueprint")

    app.register_blueprint(health_bp)
    logger.debug("Registered health blueprint")

    app.register_blueprint(control_bp)
    logger.debug("Registered control blueprint")

    app.register_blueprint(telemetry_bp)
    logger.debug("Registered telemetry blueprint")

    app.register_blueprint(auth_bp)
    logger.debug("Registered auth blueprint")


