"""Tests for API health endpoints and readiness behaviour."""

from __future__ import annotations

from flask import Response


def test_health_endpoint_returns_ok(api_client):
    """Verify `/api/health` returns 200 and basic metadata."""

    response: Response = api_client.get("/api/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert "build" in payload


def test_readiness_fails_when_auth_not_initialized(create_api_app):
    """Readiness should fail if `init_auth` has not been executed."""

    app = create_api_app()
    with app.test_client() as client:
        response: Response = client.get("/api/health/readiness")
        assert response.status_code == 503
        payload = response.get_json()
        assert payload["status"] == "degraded"


def test_readiness_succeeds_after_init_auth(monkeypatch, create_api_app):
    """Readiness should pass once `init_auth` runs successfully."""

    app = create_api_app()

    with app.app_context():
        # The test fixture forces init_auth during app creation
        pass

    with app.test_client() as client:
        response: Response = client.get("/api/health/readiness")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "ok"
        assert payload["checks"]["auth"] == "ok"

