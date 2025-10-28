"""Central route registration for the BAS API app.

Imports and registers all component blueprints so routes live in one place.
"""

from __future__ import annotations

from flask import Flask

from .ui_routes import ui_bp
from .health_routes import health_bp
from .control_routes import control_bp
from .telemetry_routes import telemetry_bp
from .auth_routes import auth_bp


def register_routes(app: Flask) -> None:
    app.register_blueprint(ui_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(control_bp)
    app.register_blueprint(telemetry_bp)
    app.register_blueprint(auth_bp)


