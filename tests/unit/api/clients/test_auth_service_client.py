"""Tests for `apps.api.clients.auth_service.AuthServiceClient`."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Mapping

import pytest

from apps.api.clients.auth_service import AuthServiceClient, AuthServiceClientConfig


class _FakeResponse:
    """Fake response for testing."""
    
    def __init__(self, *, status: int = 200, headers: Mapping[str, str] | None = None, body: Mapping[str, object] | None = None):
        self._status = status
        self.headers = headers or {}
        self._body = json.dumps(body or {}).encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return None

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self._status


@pytest.fixture(autouse=True)
def patch_service_keyset(monkeypatch):
    """Patch the service keyset."""
    
    fake_key = SimpleNamespace(kid="kid-123", alg="HS256")
    keyset = SimpleNamespace(keys=lambda: [fake_key], to_dict=lambda: {"keys": [fake_key]})
    monkeypatch.setattr("apps.api.clients.auth_service.load_service_keyset_from_env", lambda prefix: keyset)


def _make_config(**overrides) -> AuthServiceClientConfig:
    """Make a config."""

    defaults = {
        "base_url": "https://auth.example",
        "audience": "auth-service",
        "issuer": "api",
        "subject": "api-backend",
        "token_ttl_seconds": 10,
        "timeout_seconds": 5.0,
    }
    defaults.update(overrides)
    return AuthServiceClientConfig(**defaults)


def test_login_sends_expected_payload(monkeypatch):
    """Test that login sends the expected payload."""

    captured = {}

    def _fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.method
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse(body={"ok": True})

    monkeypatch.setattr("apps.api.clients.auth_service.urlopen", _fake_urlopen)
    client = AuthServiceClient(_make_config())

    response = client.login("user@example", "secret", tenant_id="tenant-1", remote_addr="1.2.3.4")

    assert response.ok is True
    assert captured["url"].endswith("/auth/login")
    assert captured["method"] == "POST"
    assert captured["body"] == {"username": "user@example", "password": "secret"}
    assert captured["headers"]["X-BAS-Tenant"] == "tenant-1"


def test_logout_attaches_cookies(monkeypatch):
    """Test that logout attaches cookies."""

    def _fake_urlopen(request, timeout):
        """Fake URL open."""

        assert "Cookie" in request.headers
        assert "Authorization" in request.headers
        return _FakeResponse(body={"status": "logged_out"})

    monkeypatch.setattr("apps.api.clients.auth_service.urlopen", _fake_urlopen)
    client = AuthServiceClient(_make_config())

    response = client.logout(cookies={"session": "abc"})
    assert response.ok is True


def test_status_handles_http_error(monkeypatch):
    """Test that status handles HTTP error."""

    class _HTTPError(Exception):
        """HTTP error for testing."""

        def __init__(self):
            self.code = 500
            self.headers = {}

        def read(self) -> bytes:
            return b"{}"

    def _fake_urlopen(request, timeout):
        raise _HTTPError()

    monkeypatch.setattr("apps.api.clients.auth_service.urlopen", _fake_urlopen)
    client = AuthServiceClient(_make_config())

    response = client.status()
    assert response.status_code == 500
    assert response.json == {}


def test_update_limits_serializes_payload(monkeypatch):
    """Test that update limits serializes the payload."""

    payloads = []

    def _fake_urlopen(request, timeout):
        payloads.append(json.loads(request.data.decode("utf-8")))
        return _FakeResponse()

    monkeypatch.setattr("apps.api.clients.auth_service.urlopen", _fake_urlopen)
    client = AuthServiceClient(_make_config())

    body = {"tenant": {"limit": 10}}
    client.update_limits(per_user_limits=body)

    assert payloads == [{"per_user_limits": body}]


def test_issue_service_token_error_propagates(monkeypatch):
    """Test that issue service token error propagates."""
    
    def _raise_token_error(*args, **kwargs):
        raise RuntimeError("token failure")

    monkeypatch.setattr("apps.api.clients.auth_service.issue_service_jwt", _raise_token_error)

    client = AuthServiceClient(_make_config())

    with pytest.raises(RuntimeError):
        client.login("user", "pass")

