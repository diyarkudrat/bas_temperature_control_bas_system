"""Tests covering API bootstrap and runtime initialization."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from adapters.providers.deny_all import DenyAllAuthProvider
from adapters.providers.mock_auth0 import MockAuth0Provider
from app_platform.observability.metrics import AuthMetrics

from tests.utils.api.firestore_stub import FirestoreStub
from tests.unit.api.conftest import _fake_server_config


def _clone_namespace(ns: SimpleNamespace) -> SimpleNamespace:
    """Clone a namespace."""
    
    return SimpleNamespace(**ns.__dict__)


def _fake_config() -> SimpleNamespace:
    """Provide a baseline fake server config for tests."""

    return _clone_namespace(_fake_server_config())


def _load_api_module(create_api_app, **builder_kwargs) -> object:
    """Load the API module."""
    
    create_api_app(**builder_kwargs)

    return importlib.import_module("apps.api.main")


def _patch_auth_dependencies(monkeypatch, api_main, *, use_firestore: bool) -> dict[str, object]:
    """Patch the auth dependencies."""

    base_config = SimpleNamespace(
        org_signup_v2_enabled=True,
        device_rbac_enforcement=True,
        provisioning_jwt_ttl_seconds=900,
        use_firestore_auth=use_firestore,
        use_firestore_audit=use_firestore,
        auth_mode="default",
    )

    monkeypatch.setattr(api_main.AuthConfig, "from_file", lambda _path: _clone_namespace(base_config))
    monkeypatch.setattr(
        api_main.AuthServiceClientConfig,
        "from_env",
        classmethod(
            lambda cls, _env=None: SimpleNamespace(
                audience="auth-service",
                issuer="issuer",
                token_ttl_seconds=30,
                allowed_algorithms=None,
            )
        ),
    )

    created_clients: list[SimpleNamespace] = []

    class _FakeAuthServiceClient:
        """Fake auth service client."""

        def __init__(self, config):
            created_clients.append(config)

    class _SecretManagerAdapter:
        """Fake secret manager adapter."""

        def __init__(self, project):
            self.project = project

    class _DeviceCredentialService:
        """Fake device credential service."""

        def __init__(self, adapter, *, rotation_hours, namespace):
            self.adapter = adapter
            self.rotation_hours = rotation_hours
            self.namespace = namespace

    monkeypatch.setattr(api_main, "AuthServiceClient", _FakeAuthServiceClient)
    monkeypatch.setattr(api_main, "SecretManagerAdapter", _SecretManagerAdapter)
    monkeypatch.setattr(api_main, "DeviceCredentialService", _DeviceCredentialService)

    return {
        "created_clients": created_clients,
        "device_service_cls": _DeviceCredentialService,
        "secret_adapter_cls": _SecretManagerAdapter,
    }


def test_build_auth_provider_auth0_success(monkeypatch, create_api_app):
    """Test that the auth0 provider is built successfully."""

    api_main = _load_api_module(create_api_app)
    sentinel = object()
    monkeypatch.setattr(api_main, "build_auth0_provider", lambda config: sentinel)

    cfg = SimpleNamespace(
        auth_provider="auth0",
        auth0_domain="tenant.auth0.test",
        auth0_audience="api://tenant",
        use_emulators=False,
    )

    provider = api_main._build_auth_provider(cfg)

    assert provider is sentinel


def test_build_auth_provider_missing_auth0_config(monkeypatch, create_api_app):
    """Test that the auth0 provider is rejected for missing config."""

    api_main = _load_api_module(create_api_app)
    monkeypatch.setattr(api_main, "build_auth0_provider", lambda _config: object())

    cfg = SimpleNamespace(auth_provider="auth0", auth0_domain="", auth0_audience="", use_emulators=False)

    provider = api_main._build_auth_provider(cfg)

    assert isinstance(provider, DenyAllAuthProvider)


def test_build_auth_provider_mock_requires_emulators(create_api_app):
    """Test that the mock provider requires emulators."""

    api_main = _load_api_module(create_api_app)

    cfg = SimpleNamespace(auth_provider="mock", auth0_domain="mock.example", auth0_audience="aud", use_emulators=True)
    provider = api_main._build_auth_provider(cfg)
    assert isinstance(provider, MockAuth0Provider)

    cfg_no_emulator = SimpleNamespace(auth_provider="mock", auth0_domain="mock.example", auth0_audience="aud", use_emulators=False)
    provider_denied = api_main._build_auth_provider(cfg_no_emulator)
    assert isinstance(provider_denied, DenyAllAuthProvider)


def test_build_auth_runtime_returns_metrics(monkeypatch, create_api_app):
    """Test that the auth runtime returns metrics."""

    api_main = _load_api_module(create_api_app)
    sentinel_provider = object()
    monkeypatch.setattr(api_main, "_build_auth_provider", lambda cfg: sentinel_provider)

    provider, metrics = api_main._build_auth_runtime(SimpleNamespace())

    assert provider is sentinel_provider
    assert isinstance(metrics, AuthMetrics)


def test_init_auth_success(monkeypatch, create_api_app):
    """Test that the auth is initialized successfully."""

    api_main = _load_api_module(create_api_app)
    patched = _patch_auth_dependencies(monkeypatch, api_main, use_firestore=False)

    assert api_main.init_auth() is True

    assert api_main.app.config["org_signup_v2_enabled"] is True
    assert api_main.app.config["device_rbac_enforcement"] is True
    assert isinstance(api_main.app.config["device_credential_service"], patched["device_service_cls"])

    client_factory = api_main.auth_service_client_factory
    assert callable(client_factory)
    client_factory()
    assert patched["created_clients"]


def test_init_auth_rejects_invalid_config(monkeypatch, create_api_app):
    """Test that the auth is rejected for invalid config."""

    api_main = _load_api_module(create_api_app)

    class _InvalidConfig(SimpleNamespace):
        def validate(self) -> bool:  # pragma: no cover
            return False

    monkeypatch.setattr(api_main.AuthConfig, "from_file", lambda _path: _InvalidConfig())

    assert api_main.init_auth() is False


def test_init_auth_handles_firestore_health(monkeypatch, create_api_app, fake_tenant_middleware):
    """Test that the auth handles firestore health."""

    def server_config_with_firestore() -> SimpleNamespace:
        """Server config with firestore."""

        cfg = _clone_namespace(_fake_server_config())
        cfg.firestore = SimpleNamespace(use_firestore_auth=True, use_firestore_audit=True)
        
        return cfg

    # Unhealthy Firestore should abort initialization
    firestore_unhealthy = FirestoreStub()
    firestore_unhealthy.set_health("unhealthy", reason="not_ready")
    api_main_unhealthy = _load_api_module(
        create_api_app,
        firestore_factory=firestore_unhealthy,
        server_config_factory=server_config_with_firestore,
    )
    _patch_auth_dependencies(monkeypatch, api_main_unhealthy, use_firestore=True)
    fake_tenant_middleware.calls.clear()

    assert api_main_unhealthy.init_auth() is False
    assert firestore_unhealthy.health_checks
    assert fake_tenant_middleware.calls == []

    # Healthy Firestore should succeed and attach tenant middleware
    firestore_healthy = FirestoreStub()
    api_main_healthy = _load_api_module(
        create_api_app,
        firestore_factory=firestore_healthy,
        server_config_factory=server_config_with_firestore,
    )
    _patch_auth_dependencies(monkeypatch, api_main_healthy, use_firestore=True)
    fake_tenant_middleware.calls.clear()

    assert api_main_healthy.init_auth() is True
    assert api_main_healthy.firestore_factory is firestore_healthy
    assert fake_tenant_middleware.calls


