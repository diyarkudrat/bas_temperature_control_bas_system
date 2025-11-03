"""Central API error codes and registration helpers."""

from __future__ import annotations

from typing import Any, Dict
from flask import jsonify, request


ERRORS: Dict[str, int] = {
    'MISSING_FIELDS': 400,
    'INVALID_ARGUMENT': 400,
    'VALIDATION_ERROR': 400,
    'NOT_FOUND': 404,
    'PERMISSION_DENIED': 403,
    'AUTH_ERROR': 401,
    'FIRESTORE_ERROR': 502,
    'DB_ERROR': 500,
    'INTERNAL_ERROR': 500,
}


def make_error(message: str, code: str) -> Any:
    """Make an error response."""

    status = ERRORS.get(code, 500)
    payload = {'error': message, 'code': code}

    # include version hint if present
    path = getattr(request, 'path', '') or ''

    if '/api/v1/' in path:
        payload['version'] = 'v1'
    elif '/api/v2/' in path:
        payload['version'] = 'v2'

    return jsonify(payload), status


def register_error_handlers(app) -> None:
    """Register error handlers."""

    try:
        from adapters.db.firestore.base import (
            FirestoreError as FsError,
            NotFoundError as FsNotFoundError,
            ValidationError as FsValidationError,
            PermissionError as FsPermissionError,
        )
    except Exception:
        class FsError(Exception):  # type: ignore
            pass
        class FsNotFoundError(FsError):  # type: ignore
            pass
        class FsValidationError(FsError):  # type: ignore
            pass
        class FsPermissionError(FsError):  # type: ignore
            pass

    try:
        from auth.exceptions import AuthError as AuthErr  # type: ignore
    except Exception:
        class AuthErr(Exception):  # type: ignore
            pass

    @app.errorhandler(404)
    def _h_404(_e):
        """Handle 404 errors."""

        return make_error('Not found', 'NOT_FOUND')

    @app.errorhandler(405)
    def _h_405(_e):
        """Handle 405 errors."""

        return make_error('Method not allowed', 'INVALID_ARGUMENT')

    @app.errorhandler(Exception)
    def _h_exc(e: Exception):
        """Handle all other errors."""

        if isinstance(e, KeyError):
            return make_error('Missing required fields', 'MISSING_FIELDS')
        if isinstance(e, ValueError):
            return make_error('Invalid argument', 'INVALID_ARGUMENT')
        if isinstance(e, FsValidationError):
            return make_error(str(e), 'VALIDATION_ERROR')
        if isinstance(e, FsNotFoundError):
            return make_error('Resource not found', 'NOT_FOUND')
        if isinstance(e, FsPermissionError):
            return make_error('Permission denied', 'PERMISSION_DENIED')
        if isinstance(e, FsError):
            return make_error('Firestore error', 'FIRESTORE_ERROR')
        if isinstance(e, AuthErr):
            return make_error('Unauthorized', 'AUTH_ERROR')

        import sqlite3

        if isinstance(e, sqlite3.Error):
            return make_error('Database error', 'DB_ERROR')

        return make_error('Internal server error', 'INTERNAL_ERROR')
