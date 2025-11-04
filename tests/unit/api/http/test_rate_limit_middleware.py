"""Tests for the global rate limit middleware."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from apps.api.http.middleware.rate_limit import enforce_global_rate_limit
from tests.utils.api.rate_limiter_stub import RateLimiterStub


@pytest.fixture
def rate_limit_config() -> SimpleNamespace:
    """Provide a baseline rate limit config for tests."""
    
    return SimpleNamespace(
        enabled=True,
        burst_capacity=2,
        requests_per_second=1.0,
        shadow_mode=False,
    )


def _enter_rate_limited_request(app, path: str, *, config: SimpleNamespace, limiter: RateLimiterStub):
    """Enter a rate limited request."""

    app.config["global_rate_limiter"] = limiter
    app.config["rate_limit_holder"] = SimpleNamespace(get_snapshot=lambda: config)

    return app.test_request_context(path, environ_overrides={"REMOTE_ADDR": "203.0.113.1"})


def test_enforce_global_rate_limit_allows(create_api_app, rate_limit_config):
    """Test that requests pass when the limiter allows."""
    
    limiter = RateLimiterStub()
    limiter.set_decision(allowed=True)
    app = create_api_app()

    with _enter_rate_limited_request(app, "/api/orgs", config=rate_limit_config, limiter=limiter):
        assert enforce_global_rate_limit() is None


def test_enforce_global_rate_limit_blocks(create_api_app, rate_limit_config):
    """Test that rate limit is enforced when the limiter denies."""
    
    limiter = RateLimiterStub()
    limiter.set_decision(allowed=False)
    app = create_api_app()

    with _enter_rate_limited_request(app, "/api/orgs", config=rate_limit_config, limiter=limiter):
        result = enforce_global_rate_limit()

    assert result is not None
    response, status = result
    assert status == 429
    assert response.get_json()["code"] == "GLOBAL_RATE_LIMITED"


def test_enforce_global_rate_limit_shadow_mode(create_api_app, rate_limit_config, caplog):
    """Test that shadow mode logs but allows."""
    
    limiter = RateLimiterStub()
    limiter.set_decision(allowed=False)
    config = SimpleNamespace(**rate_limit_config.__dict__)
    config.shadow_mode = True
    app = create_api_app()

    caplog.set_level("INFO")

    with _enter_rate_limited_request(app, "/api/orgs", config=config, limiter=limiter):
        assert enforce_global_rate_limit() is None

    assert any("shadow hit" in record.message for record in caplog.records)

