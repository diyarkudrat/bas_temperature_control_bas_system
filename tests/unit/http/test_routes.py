from __future__ import annotations

from typing import Any, Dict

import pytest


class _MockProvider:
    def __init__(self, claims: Dict[str, Any] | None = None, roles: list[str] | None = None, fail: Exception | None = None):
        self._claims = claims or {}
        self._roles = roles or []
        self._fail = fail

    def verify_token(self, token: str):  # noqa: ARG002
        if self._fail:
            raise self._fail
        return dict(self._claims)

    def get_user_roles(self, uid: str):  # noqa: ARG002
        return list(self._roles)

    def healthcheck(self):
        return {"status": "ok"}


class _Cfg:
    auth_enabled = True
    auth_mode = "enforced"
    tenant_id_header = "X-BAS-Tenant"
    allow_session_fallback = False


@pytest.fixture(autouse=True)
def _ensure_enforced_auth(monkeypatch):
    # Force enforced mode with no fallback for JWT tests
    import bas_server as srv
    monkeypatch.setattr(srv, "auth_config", _Cfg())
    yield


def test_protected_route_jwt_valid(monkeypatch):
    import bas_server as srv
    app = srv.app
    provider = _MockProvider(claims={"sub": "u1"}, roles=["operator", "read-only"])  # sufficient for both endpoints

    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            from flask import request
            request.auth_provider = provider

        # GET telemetry (read-only)
        rv = c.get("/api/telemetry", headers={"Authorization": "Bearer good", "X-BAS-Tenant": "t1"})
        assert rv.status_code == 200

        # POST set_setpoint (operator)
        rv2 = c.post("/api/set_setpoint", json={"setpoint_tenths": 250}, headers={"Authorization": "Bearer good"})
        assert rv2.status_code == 200


def test_protected_route_jwt_invalid(monkeypatch):
    import bas_server as srv
    app = srv.app
    provider = _MockProvider(fail=ValueError("expired"))

    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            from flask import request
            request.auth_provider = provider

        rv = c.get("/api/telemetry", headers={"Authorization": "Bearer bad", "X-BAS-Tenant": "t1"})
        assert rv.status_code == 401
        data = rv.get_json()
        assert data["code"] in {"INVALID_TOKEN", "TOKEN_EXPIRED"}


def test_unauth_401_consistency():
    import bas_server as srv
    app = srv.app
    with app.test_client() as c:
        # No Authorization and no session
        rv = c.get("/api/telemetry")
        assert rv.status_code == 401


def test_role_based_403():
    import bas_server as srv
    app = srv.app
    provider = _MockProvider(claims={"sub": "u2"}, roles=["read-only"])  # insufficient for operator

    with app.test_client() as c:
        @app.before_request
        def _set_provider():
            from flask import request
            request.auth_provider = provider

        rv = c.post("/api/set_setpoint", json={"setpoint_tenths": 250}, headers={"Authorization": "Bearer good"})
        assert rv.status_code == 403


