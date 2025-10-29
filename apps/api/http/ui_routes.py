"""UI routes (dashboard and login page)."""

from __future__ import annotations

from flask import Blueprint, redirect, request

from apps.api.http import routes as http_routes


ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def dashboard():
    # Redirect unauthenticated users to login instead of JSON error
    session_id = request.cookies.get('bas_session_id') or request.headers.get('X-Session-ID')
    if not session_id:
        return redirect('/auth/login', 302)

    # Validate session if manager is available
    sm = getattr(request, 'session_manager', None)
    if sm is not None:
        if not sm.validate_session(session_id, request):
            return redirect('/auth/login', 302)

    return http_routes.dashboard()


@ui_bp.route("/auth/login")
def auth_login_page():
    return http_routes.auth_login_page()


