"""HTTP versioning helpers for Flask apps (composable with security headers)."""

from __future__ import annotations

from typing import Optional, Callable
from flask import request


def get_version_from_path(path: str) -> str:
    """Infer API version string ('1' or '2') from a URL path."""
    if path.startswith('/api/v1/'):
        return '1'
    if path.startswith('/api/v2/'):
        return '2'
    # Default unversioned /api/* to v2 semantics
    if path.startswith('/api/'):
        return '2'
    return ''


def build_versioning_applier(*, sunset_v1_http_date: Optional[str] = None, deprecate_v1: bool = True) -> Callable:
    """Return a function(response) -> response that applies versioning headers."""
    sunset_value = sunset_v1_http_date or 'Wed, 01 Jan 2026 00:00:00 GMT'

    def _apply(response):
        try:
            version = get_version_from_path(request.path or '')
            if version:
                response.headers['API-Version'] = version
                if version == '1' and deprecate_v1:
                    response.headers['Deprecation'] = 'true'
                    response.headers['Sunset'] = sunset_value
            return response
        except Exception:
            return response

    return _apply


