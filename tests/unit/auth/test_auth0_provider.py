from __future__ import annotations

import json
import time
from typing import Dict, Any

import pytest
from jose import jwt

from server.auth.providers.auth0 import Auth0Provider


def _generate_rsa_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_numbers = private_key.public_key().public_numbers()
    n_int = public_numbers.n
    e_int = public_numbers.e
    return private_pem, n_int, e_int


def _b64url_uint(data: int) -> str:
    import base64

    length = (data.bit_length() + 7) // 8 or 1
    raw = data.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _FakeHTTPResponse:
    def __init__(self, payload: Dict[str, Any]):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _mint_token(private_pem: str, issuer: str, audience: str, subject: str, kid: str, expires_in_s: int = 60, issued_at_s: int | None = None, extra: Dict[str, Any] | None = None) -> str:
    now = int(issued_at_s if issued_at_s is not None else time.time())
    payload: Dict[str, Any] = {
        "sub": subject,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "exp": now + int(expires_in_s),
    }
    if extra:
        payload.update(extra)
    headers = {"kid": kid, "alg": "RS256", "typ": "JWT"}
    return jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)


def test_fetch_jwks_success(monkeypatch):
    private_pem, n_int, e_int = _generate_rsa_keypair()
    kid = "kid-123"
    jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64url_uint(n_int), "e": _b64url_uint(e_int)}]}

    def fake_urlopen(url, timeout=5):  # noqa: ARG001
        return _FakeHTTPResponse(jwks)

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen)

    provider = Auth0Provider(issuer="https://tenant.auth0.com/", audience="bas-api")
    fetched = provider._fetch_jwks()  # type: ignore[attr-defined]
    assert fetched["keys"][0]["kid"] == kid


def test_fetch_jwks_failure(monkeypatch):
    class FakeError(Exception):
        pass

    def fake_urlopen(url, timeout=5):  # noqa: ARG001
        raise FakeError("boom")

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen)
    provider = Auth0Provider(issuer="https://tenant.auth0.com/", audience="bas-api")
    with pytest.raises(ValueError):
        provider._fetch_jwks()  # type: ignore[attr-defined]


def test_verify_valid_jwt(monkeypatch):
    private_pem, n_int, e_int = _generate_rsa_keypair()
    kid = "kid-valid"
    issuer = "https://tenant.auth0.com/"
    audience = "bas-api"
    jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64url_uint(n_int), "e": _b64url_uint(e_int)}]}

    def fake_urlopen(url, timeout=5):  # noqa: ARG001
        return _FakeHTTPResponse(jwks)

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen)
    provider = Auth0Provider(issuer=issuer, audience=audience)

    token = _mint_token(private_pem, issuer, audience, subject="user123", kid=kid, extra={"roles": ["operator"]})
    claims = provider.verify_token(token)
    assert claims["sub"] == "user123"
    assert provider.get_user_roles("user123") == ["operator"]


def test_verify_invalid_alg(monkeypatch):
    private_pem, n_int, e_int = _generate_rsa_keypair()
    kid = "kid-a"
    issuer = "https://tenant.auth0.com/"
    audience = "bas-api"
    jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64url_uint(n_int), "e": _b64url_uint(e_int)}]}

    def fake_urlopen(url, timeout=5):  # noqa: ARG001
        return _FakeHTTPResponse(jwks)

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen)
    provider = Auth0Provider(issuer=issuer, audience=audience)

    # Create HS256 token to trigger alg rejection
    now = int(time.time())
    payload = {"sub": "userX", "aud": audience, "iss": issuer, "iat": now, "exp": now + 60}
    token_hs = jwt.encode(payload, "secret", algorithm="HS256", headers={"kid": kid})
    with pytest.raises(ValueError):
        provider.verify_token(token_hs)


def test_verify_expired_jwt(monkeypatch):
    private_pem, n_int, e_int = _generate_rsa_keypair()
    kid = "kid-exp"
    issuer = "https://tenant.auth0.com/"
    audience = "baseline"
    jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64url_uint(n_int), "e": _b64url_uint(e_int)}]}

    def fake_urlopen(url, timeout=5):  # noqa: ARG001
        return _FakeHTTPResponse(jwks)

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen)
    provider = Auth0Provider(issuer=issuer, audience=audience)

    token = _mint_token(private_pem, issuer, audience, subject="userZ", kid=kid, expires_in_s=-10)
    with pytest.raises(ValueError):
        provider.verify_token(token)


def test_cache_invalidation(monkeypatch):
    private_pem, n_int, e_int = _generate_rsa_keypair()
    kid = "kid-iv"
    issuer = "https://tenant.auth0.com/"
    audience = "bas-api"
    jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64url_uint(n_int), "e": _b64url_uint(e_int)}]}

    def fake_urlopen_ok(url, timeout=5):  # noqa: ARG001
        return _FakeHTTPResponse(jwks)

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen_ok)
    provider = Auth0Provider(issuer=issuer, audience=audience)

    token = _mint_token(private_pem, issuer, audience, subject="userC", kid=kid)
    # Prime cache
    claims = provider.verify_token(token)
    assert claims["sub"] == "userC"

    # Invalidate and simulate JWKS fetch failure
    provider.invalidate_cache()

    def fake_urlopen_fail(url, timeout=5):  # noqa: ARG001
        raise RuntimeError("network down")

    monkeypatch.setattr("server.auth.providers.auth0.urlopen", fake_urlopen_fail)
    with pytest.raises(ValueError):
        provider.verify_token(token)


class _MgmtConflict(Exception):
    def __init__(self, message: str = "conflict", status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


class _FakeManagementClient:
    def __init__(self, conflict_once: bool = True):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._conflict_once = conflict_once

    def get_user_metadata(self, user_id: str) -> Dict[str, Any]:
        return self._store.get(user_id, {})

    def update_user_metadata(self, user_id: str, payload: Dict[str, Any], expected_version: int | None, idempotency_key: str) -> Dict[str, Any]:  # noqa: ARG002
        cur = self._store.get(user_id, {})
        app_meta = cur.get("app_metadata", {}) if isinstance(cur, dict) else {}
        bas_roles = app_meta.get("bas_roles", {}) if isinstance(app_meta, dict) else {}
        current_version = bas_roles.get("version") if isinstance(bas_roles, dict) else None

        # Simulate one-time conflict
        if self._conflict_once:
            self._conflict_once = False
            raise _MgmtConflict()

        # CAS: if expected_version is provided and doesn't match, raise conflict
        if expected_version is not None and expected_version != current_version:
            raise _MgmtConflict()

        # Apply update
        self._store[user_id] = payload
        return payload


def test_set_user_roles_tx(monkeypatch):  # noqa: ARG001
    provider = Auth0Provider(issuer="https://tenant.auth0.com/", audience="bas-api")

    mgmt = _FakeManagementClient(conflict_once=True)
    user_id = "user-1"
    roles = {"operator": True, "viewer": True}

    # First call should handle a transient conflict and then succeed
    result = provider.set_user_roles(user_id, roles, management_client=mgmt, max_retries=3, initial_backoff_s=0.0)
    assert "app_metadata" in result
    assert result["app_metadata"]["bas_roles"]["roles"] == roles
    assert result["app_metadata"]["bas_roles"]["version"] == 1

    # Second update should increment version
    roles2 = {"operator": True}
    result2 = provider.set_user_roles(user_id, roles2, management_client=mgmt, max_retries=0, initial_backoff_s=0.0)
    assert result2["app_metadata"]["bas_roles"]["roles"] == roles2
    assert result2["app_metadata"]["bas_roles"]["version"] == 2


def test_get_user_roles_versioned(monkeypatch):  # noqa: ARG001
    provider = Auth0Provider(issuer="https://tenant.auth0.com/", audience="bas-api", roles_cache_ttl_s=3600)

    mgmt = _FakeManagementClient(conflict_once=False)
    user_id = "user-2"

    # No metadata yet → fallback to claims (empty)
    assert provider.get_user_roles(user_id) == []

    # Write roles via set_user_roles (version 1)
    provider.set_user_roles(user_id, {"operator": True, "viewer": 1}, management_client=mgmt, max_retries=0, initial_backoff_s=0.0)
    roles_v1 = provider.get_user_roles(user_id)
    assert roles_v1 == ["operator", "viewer"]

    # Update to version 2 with different roles
    provider.set_user_roles(user_id, {"operator": True}, management_client=mgmt, max_retries=0, initial_backoff_s=0.0)
    roles_v2 = provider.get_user_roles(user_id)
    assert roles_v2 == ["operator"]

