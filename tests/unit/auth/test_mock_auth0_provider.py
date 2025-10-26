from __future__ import annotations

import time
import pytest

from auth.providers import MockAuth0Provider
from tests.fixtures.auth.mock_tokens import mint_token


def test_healthcheck_contains_expected_fields():
    provider = MockAuth0Provider()
    health = provider.healthcheck()
    assert health["provider"] == "MockAuth0Provider"
    assert health["status"] == "ok"
    assert health["mode"] == "mock"
    assert "now_epoch_ms" in health


def test_verify_success_with_generated_keys():
    provider = MockAuth0Provider(audience="bas-api", issuer="https://mock.auth0/")
    priv = provider.private_key_pem
    assert isinstance(priv, str) and len(priv) > 0
    token = mint_token(priv, audience="bas-api", issuer="https://mock.auth0/", subject="u1")
    claims = provider.verify_token(token)
    assert claims["sub"] == "u1"


def test_verify_expired_token_raises():
    provider = MockAuth0Provider(audience="bas-api", issuer="https://mock.auth0/")
    priv = provider.private_key_pem
    token = mint_token(priv, audience="bas-api", issuer="https://mock.auth0/", subject="u2", expires_in_s=-1)
    with pytest.raises(ValueError):
        provider.verify_token(token)


def test_verify_bad_audience_raises():
    provider = MockAuth0Provider(audience="bas-api", issuer="https://mock.auth0/")
    priv = provider.private_key_pem
    token = mint_token(priv, audience="wrong", issuer="https://mock.auth0/", subject="u3")
    with pytest.raises(ValueError):
        provider.verify_token(token)


def test_verify_bad_issuer_raises():
    provider = MockAuth0Provider(audience="bas-api", issuer="https://mock.auth0/")
    priv = provider.private_key_pem
    token = mint_token(priv, audience="bas-api", issuer="https://other/", subject="u4")
    with pytest.raises(ValueError):
        provider.verify_token(token)


def test_roles_lookup_static_map():
    provider = MockAuth0Provider(roles_map={"u1": ["admin", "operator"]})
    assert provider.get_user_roles("u1") == ["admin", "operator"]
    assert provider.get_user_roles("u2") == []


def test_mock_roles_injected_failures_and_cache_behavior():
    provider = MockAuth0Provider(roles_cache_ttl_s=3600)

    # Inject a transient set failure, then succeed on retry
    provider.inject_failure(set=1)
    with pytest.raises(ValueError):
        provider.set_user_roles("u1", {"admin": True}, max_retries=0)
    res = provider.set_user_roles("u1", {"admin": True}, max_retries=0)
    assert res["app_metadata"]["bas_roles"]["roles"] == ["admin"]

    # Roles are cached
    assert provider.get_user_roles("u1") == ["admin"]

    # Inject a read failure; cache still serves
    provider.inject_failure(get=1)
    assert provider.get_user_roles("u1") == ["admin"]

    # Conflict injection then success
    provider.inject_failure(conflict=1)
    with pytest.raises(ValueError):
        provider.set_user_roles("u1", {"operator": True}, max_retries=0)
    provider.set_user_roles("u1", {"operator": True}, max_retries=0)
    assert provider.get_user_roles("u1") == ["operator"]

