"""UI routes (dashboard and login page)."""

from __future__ import annotations

from flask import Blueprint

from apps.api.http import routes as http_routes


ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def dashboard():
    return http_routes.dashboard()


@ui_bp.route("/auth/login")
def auth_login_page():
    return http_routes.auth_login_page()


