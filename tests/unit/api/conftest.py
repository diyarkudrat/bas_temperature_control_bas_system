"""API service specific fixtures for unit tests."""

from __future__ import annotations

import importlib
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Mapping, MutableMapping

import pytest
from flask import Flask, Request

from tests.utils.flask_client_factory import flask_test_client


@dataclass
class _FakeTenantContext:
    """Fake tenant context for testing."""

    tenant_id: str = "tenant-test"
    region: str = "us-test-1"


class _FakeTenantMiddleware:
    """Fake tenant middleware for testing."""

    def __init__(self) -> None:
        self.calls: list[Request] = []

    def setup_tenant_context(self, request: Request) -> None:  # pragma: no cover - exercised via fixtures
        """Setup tenant context."""

        request._tenant_context = _FakeTenantContext()
        self.calls.append(request)


class _FakeAuthProvider:
    """Fake auth provider for testing."""

    def __init__(self) -> None:
        """Initialize auth provider."""

        self.tokens: list[str] = []

    def validate(self, token: str, **_kwargs: Any) -> Mapping[str, Any]:  # pragma: no cover - exercised in tests
        """Validate token."""

        self.tokens.append(token)
        return {"sub": "user-test", "scope": ["read"]}

    def authorize(self, *_args: Any, **_kwargs: Any) -> bool:  # pragma: no cover - simple stub
        """Authorize."""

        return True


class _FakeAuthServiceClient:
    """Fake auth service client for testing."""

    def __init__(self) -> None:
        """Initialize auth service client."""

        self.requests: list[tuple[tuple[Any, ...], Mapping[str, Any]]] = []

    def fetch_token(self, *args: Any, **kwargs: Any) -> SimpleNamespace:
        """Fetch token."""

        self.requests.append((args, kwargs))
        return SimpleNamespace(access_token="token", expires_in=60)


def _fake_server_config() -> SimpleNamespace:
    """Fake server config for testing."""

    firestore = SimpleNamespace(use_firestore_auth=False, use_firestore_audit=False)
    org_flows = SimpleNamespace(
        org_signup_v2_enabled=False,
        device_rbac_enforcement=False,
        device_credential_rotation_hours=24,
        secret_manager_project="test-project",
    )
    rate_limit = SimpleNamespace(global_limit=1000, burst_limit=100, refill_rate_per_sec=10)
    
    return SimpleNamespace(
        auth_provider="mock",
        auth0_domain="mock.auth0.test",
        auth0_audience="api://test",
        use_emulators=True,
        firestore=firestore,
        rate_limit=rate_limit,
        org_flows=org_flows,
        gcp_project_id="test-project",
    )


@pytest.fixture(autouse=True)
def _api_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Standardize environment toggles for deterministic API unit tests."""

    monkeypatch.setenv("BAS_DISABLE_PLUGINS", "1")
    monkeypatch.setenv("BAS_ENV", "test")
    monkeypatch.setenv("SERVER_V1_DEPRECATE", "false")
    monkeypatch.delenv("SERVER_V1_SUNSET", raising=False)


@pytest.fixture
def fake_auth_provider() -> _FakeAuthProvider:
    return _FakeAuthProvider()


@pytest.fixture
def fake_tenant_middleware() -> _FakeTenantMiddleware:
    return _FakeTenantMiddleware()


@pytest.fixture
def fake_auth_service_client() -> _FakeAuthServiceClient:
    return _FakeAuthServiceClient()


@pytest.fixture
def fake_auth_metrics() -> SimpleNamespace:
    return SimpleNamespace(record=lambda *_a, **_kw: None, increment=lambda *_a, **_kw: None)


def _reload_api_module(  # pragma: no cover - exercised through fixtures
    monkeypatch: pytest.MonkeyPatch,
    *,
    server_config: SimpleNamespace,
    tenant_middleware: _FakeTenantMiddleware,
    firestore_factory: Any | None,
) -> Any:
    """Reload the API module."""
    
    module_name = "apps.api.main"
    monkeypatch.setattr("apps.api.bootstrap.get_server_config", lambda: server_config)
    monkeypatch.setattr("apps.api.bootstrap.build_firestore_factory", lambda _cfg: firestore_factory)
    monkeypatch.setattr(
        "apps.api.bootstrap.build_tenant_middleware",
        lambda _auth_cfg, _factory: tenant_middleware,
    )

    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


@pytest.fixture
def create_api_app(
    monkeypatch: pytest.MonkeyPatch,
    fake_auth_provider: _FakeAuthProvider,
    fake_auth_service_client: _FakeAuthServiceClient,
    fake_auth_metrics: SimpleNamespace,
    fake_tenant_middleware: _FakeTenantMiddleware,
) -> Callable[[Mapping[str, Any] | None, MutableMapping[str, Any] | None], Flask]:
    """Factory fixture producing fresh API app instances with test doubles injected."""

    def _builder(
        config_overrides: Mapping[str, Any] | None = None,
        base_context: MutableMapping[str, Any] | None = None,
        *,
        firestore_factory: Any | None = None,
        server_config_factory: Callable[[], SimpleNamespace] = _fake_server_config,
    ) -> Flask:
        """Build an API app with test doubles injected."""
        
        server_config = server_config_factory()
        module = _reload_api_module(
            monkeypatch,
            server_config=server_config,
            tenant_middleware=fake_tenant_middleware,
            firestore_factory=firestore_factory,
        )

        module.auth_provider = fake_auth_provider
        module.auth_metrics = fake_auth_metrics
        module.auth_service_client_factory = lambda: fake_auth_service_client
        module.tenant_middleware = fake_tenant_middleware
        module.firestore_factory = firestore_factory

        app = module.app
        app.config.update(
            TESTING=True,
            SERVER_NAME="api.test",
            SECRET_KEY="test-secret",
        )
        if config_overrides:
            app.config.update(config_overrides)
        if base_context:
            app.config.setdefault("test_base_context", dict(base_context))

        return app

    return _builder


@pytest.fixture
def api_app(create_api_app: Callable[[], Flask]) -> Flask:
    return create_api_app()


@pytest.fixture
def api_client(create_api_app: Callable[[], Flask]):
    """Yield a test client for the API app."""
    
    with flask_test_client(create_api_app) as (_app, client):
        yield client


@pytest.fixture
def api_request_context(create_api_app: Callable[[], Flask]):
    """Context manager yielding Flask request objects for targeted assertions."""

    @contextmanager
    def _ctx(
        path: str = "/",
        *,
        method: str = "GET",
        headers: Mapping[str, Any] | None = None,
        json: Any | None = None,
        config_overrides: Mapping[str, Any] | None = None,
    ) -> Iterator[Request]:
        """Yield a test request context for the API app."""
        
        app = create_api_app(config_overrides=config_overrides)
        with app.test_request_context(path, method=method, headers=headers, json=json) as ctx:
            yield ctx.request

    return _ctx
