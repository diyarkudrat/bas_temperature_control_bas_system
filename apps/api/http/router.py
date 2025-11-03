"""Central route registration for the BAS API app.

Imports and registers all component blueprints so routes live in one place.
"""

from __future__ import annotations

from flask import Flask

from logging_lib import get_logger as get_structured_logger

from .ui_routes import ui_bp
from .health_routes import health_bp
from .control_routes import control_bp
from .auth_routes import auth_bp
from .org_routes import org_bp


def register_routes(app: Flask) -> None:
    """Register the routes for the API."""
    
    logger = get_structured_logger("api.http.router")

    app.register_blueprint(ui_bp)
    logger.debug("Registered UI blueprint")

    app.register_blueprint(health_bp)
    logger.debug("Registered health blueprint")

    app.register_blueprint(control_bp)
    logger.debug("Registered control blueprint")

    app.register_blueprint(auth_bp)
    logger.debug("Registered auth blueprint")

    if app.config.get("org_signup_v2_enabled", False):
        app.register_blueprint(org_bp)
        logger.debug("Registered org blueprint", extra={"feature_flag": True})
    else:
        logger.debug("Skipped org blueprint", extra={"feature_flag": False})


