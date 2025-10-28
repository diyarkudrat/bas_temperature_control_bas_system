"""Security headers middleware (new home).

Provides `add_security_headers(response)` without relying on legacy server.* modules.
"""

def add_security_headers(response):
    """Add security headers to response."""
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    for header, value in security_headers.items():
        response.headers[header] = value
    return response

__all__ = ["add_security_headers"]


