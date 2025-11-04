"""Tests for security header middleware and versioning hooks."""

from __future__ import annotations

from flask import Response


def test_security_headers_applied(api_client):
    """Test that security headers are applied."""

    response: Response = api_client.get("/api/health")

    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Strict-Transport-Security"].startswith("max-age")


def test_versioning_header_added(api_client):
    """Test that versioning header is added."""
    
    response: Response = api_client.get("/api/health")

    assert "Sunset" in response.headers
    assert "Deprecation" in response.headers

