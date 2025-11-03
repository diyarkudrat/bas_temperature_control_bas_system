"""Security headers middleware (new home).

Provides `add_security_headers(response)` without relying on legacy server.* modules.
"""

_CSP_DIRECTIVES = {
    "default-src": "'self'",
    "base-uri": "'self'",
    "frame-ancestors": "'none'",
    "object-src": "'none'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self' data:",
    "connect-src": "'self'",
    "font-src": "'self'",
}

_PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), fullscreen=(), payment=(), "
    "usb=(), clipboard-read=(), clipboard-write=(self)"
)


def _compose_csp(directives: dict[str, str]) -> str:
    return "; ".join(f"{directive} {value}" for directive, value in directives.items())


def add_security_headers(response):
    """Add security headers for API responses."""

    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": _compose_csp(_CSP_DIRECTIVES),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": _PERMISSIONS_POLICY,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    for header, value in security_headers.items():
        response.headers.setdefault(header, value)

    return response

__all__ = ["add_security_headers"]


