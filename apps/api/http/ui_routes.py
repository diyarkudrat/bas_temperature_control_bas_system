"""UI routes (dashboard and login page)."""

from __future__ import annotations

import hashlib

from flask import Blueprint, redirect, request

from logging_lib import get_logger as get_structured_logger

from apps.api.http import routes as http_routes


ui_bp = Blueprint("ui", __name__)

logger = get_structured_logger("api.http.ui")


def _scrub_identifier(value: str | None) -> str | None:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


@ui_bp.route("/")
def dashboard():
    # Redirect unauthenticated users to login instead of JSON error
    session_id = request.cookies.get('bas_session_id') or request.headers.get('X-Session-ID')
    if not session_id:
        logger.info("UI dashboard redirect: missing session")
        return redirect('/auth/login', 302)

    # Validate session if manager is available
    sm = getattr(request, 'session_manager', None)
    if sm is not None:
        if not sm.validate_session(session_id, request):
            logger.info(
                "UI dashboard redirect: session invalid",
                extra={"session_hash": _scrub_identifier(session_id)},
            )
            return redirect('/auth/login', 302)

    logger.debug(
        "UI dashboard served",
        extra={"session_hash": _scrub_identifier(session_id)},
    )
    return http_routes.dashboard()


@ui_bp.route("/auth/login")
def auth_login_page():
    logger.debug("UI auth login page served")
    return http_routes.auth_login_page()


