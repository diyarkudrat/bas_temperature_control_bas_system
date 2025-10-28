from __future__ import annotations

import pytest

from adapters.providers import build_auth0_provider, Auth0Provider


def test_auth0_factory_valid():
    cfg = {
        "issuer": "https://example-tenant.auth0.com/",
        "audience": "bas-api",
    }
    provider = build_auth0_provider(cfg)
    assert isinstance(provider, Auth0Provider)
    assert provider.issuer == "https://example-tenant.auth0.com/"
    assert provider.audience == "bas-api"
    # jwks_url should default from issuer
    assert provider.jwks_url.startswith("https://example-tenant.auth0.com/")


@pytest.mark.parametrize(
    "cfg,expected_err",
    [
        ({"audience": "bas-api"}, "issuer"),
        ({"issuer": "https://t/"}, "audience"),
        ({"issuer": "http://insecure.auth0.com/", "audience": "a"}, "https"),
        ({"issuer": "https://ok/", "audience": "a", "jwks_url": "http://bad"}, "jwks_url"),
        ({"issuer": "https://ok/", "audience": "a", "clock_skew_s": "abc"}, "integer"),
    ],
)
def test_auth0_factory_invalid_config(cfg, expected_err):
    with pytest.raises(ValueError) as ei:
        build_auth0_provider(cfg)
    assert expected_err in str(ei.value)


