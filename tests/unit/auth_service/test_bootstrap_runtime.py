"""Tests covering auth service runtime bootstrapping and service tokens."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from flask import Flask

from tests.utils.env import environment


def _reload_module(monkeypatch: pytest.MonkeyPatch):
    """Reload the auth service main module to ensure clean globals per test."""

    module_name = "apps.auth_service.main"
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


@pytest.fixture
def _bootstrap_stubs(monkeypatch: pytest.MonkeyPatch):
    """Prime deterministic test doubles for runtime bootstrap."""

    module = _reload_module(monkeypatch)

    validate_calls: List[str] = []

    class _FakeAuthConfig(SimpleNamespace):
        def validate(self) -> None:
            validate_calls.append("validate")

    auth_config = _FakeAuthConfig(
        auth_enabled=True,
        org_signup_v2_enabled=True,
        device_rbac_enforcement=True,
        use_firestore_auth=True,
        use_firestore_audit=False,
        provisioning_jwt_ttl_seconds=45,
        auth0_webhook_secret="sek",
    )

    monkeypatch.setattr(module.AuthConfig, "from_file", classmethod(lambda cls, _path: auth_config))

    server_config = SimpleNamespace(
        rate_limit=SimpleNamespace(global_limit=1),
        breaker=SimpleNamespace(failure_threshold=7, window_seconds=30, half_open_after_seconds=10),
        auth0_mgmt=SimpleNamespace(domain="auth0.local", enabled=True),
    )
    monkeypatch.setattr(module, "get_server_config", lambda: server_config)

    firestore_calls: List[SimpleNamespace] = []
    monkeypatch.setattr("apps.api.bootstrap.build_firestore_factory", lambda cfg: firestore_calls.append(cfg) or "firestore-factory")

    rate_limit_calls: List[Any] = []

    class _FakeAtomicRateLimitConfig:
        def __init__(self, config):
            self.config = config
            rate_limit_calls.append(config)

    monkeypatch.setattr(module, "AtomicRateLimitConfig", _FakeAtomicRateLimitConfig)

    class _Recorder:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    user_manager = []
    session_manager = []
    audit_logger = []
    rate_limiter = []

    class _FakeUserManager(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            user_manager.append(self)

    class _FakeSessionManager(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            session_manager.append(self)

    class _FakeAuditLogger(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            audit_logger.append(self)

    class _FakeRateLimiter(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            rate_limiter.append(self)

    monkeypatch.setattr(module, "UserManager", _FakeUserManager)
    monkeypatch.setattr(module, "SessionManager", _FakeSessionManager)
    monkeypatch.setattr(module, "AuditLogger", _FakeAuditLogger)
    monkeypatch.setattr(module, "RateLimiter", _FakeRateLimiter)

    class _FakeCircuitBreaker:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(module, "CircuitBreaker", lambda **kwargs: _FakeCircuitBreaker(**kwargs))

    class _FakeSession:
        def __init__(self):
            self.headers: Dict[str, str] = {}

    monkeypatch.setattr(module.requests, "Session", _FakeSession)

    auth0_clients: List[Any] = []

    class _FakeAuth0Client:
        def __init__(self, config, http_session, breaker):
            self.config = config
            self.http_session = http_session
            self.breaker = breaker
            self.enabled = True
            auth0_clients.append(self)

    monkeypatch.setattr(module, "Auth0ManagementClient", _FakeAuth0Client)

    provisioning_services: List[Any] = []
    invite_services: List[Any] = []
    verification_services: List[Any] = []

    class _FakeProvisioningService(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            provisioning_services.append(self)

    class _FakeInviteService(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            invite_services.append(self)

    class _FakeVerificationService(_Recorder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            verification_services.append(self)

    monkeypatch.setattr(module, "ProvisioningTokenService", _FakeProvisioningService)
    monkeypatch.setattr(module, "InviteService", _FakeInviteService)
    monkeypatch.setattr(module, "EmailVerificationService", _FakeVerificationService)

    service_tokens = SimpleNamespace(
        keyset=SimpleNamespace(default_kid="kid-1"),
        audience="svc-aud",
        issuer="svc-issuer",
        required_scopes=("auth.update",),
    )
    monkeypatch.setattr(module, "_build_service_token_settings", lambda: service_tokens)

    replay_calls: List[Dict[str, Any]] = []

    def _fake_replay_cache(*, prefix: str, namespace: str, **kwargs) -> SimpleNamespace:
        payload = {"prefix": prefix, "namespace": namespace, **kwargs}
        replay_calls.append(payload)
        sentinel = SimpleNamespace(**payload)
        sentinel._redis = object()
        return sentinel

    monkeypatch.setattr(module, "load_replay_cache_from_env", _fake_replay_cache)

    return SimpleNamespace(
        module=module,
        auth_config=auth_config,
        server_config=server_config,
        rate_limit_calls=rate_limit_calls,
        validate_calls=validate_calls,
        user_manager=user_manager,
        session_manager=session_manager,
        audit_logger=audit_logger,
        rate_limiter=rate_limiter,
        auth0_clients=auth0_clients,
        provisioning_services=provisioning_services,
        invite_services=invite_services,
        verification_services=verification_services,
        service_tokens=service_tokens,
        replay_calls=replay_calls,
    )


def test_bootstrap_runtime_configures_dependencies(_bootstrap_stubs, monkeypatch: pytest.MonkeyPatch) -> None:
    """`bootstrap_runtime` should wire config, service tokens, and dependencies."""

    module = _bootstrap_stubs.module
    app = Flask("auth-runtime-test")

    with environment(
        overrides={
            "AUTH_SERVICE_DB_PATH": "/tmp/auth-runtime.db",
            "AUTH_EVENTS_TIMEOUT_S": "7",
            "API_SERVICE_URL": "https://api.local",
        }
    ):
        runtime = module.bootstrap_runtime(app, config_path="/fake/config.json")

    assert runtime.config is _bootstrap_stubs.auth_config
    assert runtime.server_config is _bootstrap_stubs.module.get_server_config()

    assert _bootstrap_stubs.validate_calls == ["validate"]
    assert _bootstrap_stubs.rate_limit_calls == [_bootstrap_stubs.server_config.rate_limit]
    assert app.config["AUTH_SERVICE_RUNTIME"] is runtime
    assert app.config["rate_limit_holder"].config is _bootstrap_stubs.server_config.rate_limit
    assert app.config["SERVICE_TOKENS"] is _bootstrap_stubs.service_tokens
    assert app.config["ORG_SIGNUP_V2_ENABLED"] is True
    assert app.config["DEVICE_RBAC_ENFORCEMENT"] is True

    assert runtime.firestore_factory == "firestore-factory"
    assert runtime.user_manager is _bootstrap_stubs.user_manager[0]
    assert runtime.session_manager is _bootstrap_stubs.session_manager[0]
    assert runtime.audit_logger is _bootstrap_stubs.audit_logger[0]
    assert runtime.rate_limiter is _bootstrap_stubs.rate_limiter[0]
    assert runtime.auth0_mgmt_client is _bootstrap_stubs.auth0_clients[0]
    assert runtime.provisioning_service is _bootstrap_stubs.provisioning_services[0]
    assert runtime.invite_service is _bootstrap_stubs.invite_services[0]
    assert runtime.verification_service is _bootstrap_stubs.verification_services[0]

    http_session = runtime.http_session
    assert http_session.headers["User-Agent"] == "bas-auth-service/1.0"

    # Two replay caches should be instantiated: service tokens and email events.
    prefixes = {call["prefix"] for call in _bootstrap_stubs.replay_calls}
    assert prefixes == {"SERVICE_JWT", "AUTH_EVENTS"}


def test_bootstrap_runtime_disables_auth0_when_client_not_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auth0 client should be cleared when the constructed client reports disabled."""

    module = _reload_module(monkeypatch)

    auth_config = SimpleNamespace(
        auth_enabled=True,
        org_signup_v2_enabled=False,
        device_rbac_enforcement=False,
        use_firestore_auth=False,
        use_firestore_audit=False,
        provisioning_jwt_ttl_seconds=30,
    )
    monkeypatch.setattr(module.AuthConfig, "from_file", classmethod(lambda cls, _path: auth_config))
    monkeypatch.setattr(module, "get_server_config", lambda: SimpleNamespace(
        rate_limit=SimpleNamespace(global_limit=1),
        breaker=SimpleNamespace(failure_threshold=5, window_seconds=10, half_open_after_seconds=5),
        auth0_mgmt=SimpleNamespace(domain="auth0.local", enabled=False),
    ))

    class _DisabledClient:
        def __init__(self, *_args, **_kwargs):
            self.enabled = False

    monkeypatch.setattr(module, "Auth0ManagementClient", _DisabledClient)
    monkeypatch.setattr(module, "AtomicRateLimitConfig", lambda cfg: SimpleNamespace(config=cfg))
    monkeypatch.setattr(module, "UserManager", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "SessionManager", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "AuditLogger", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "RateLimiter", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "_build_service_token_settings", lambda: None)
    monkeypatch.setattr(module, "load_replay_cache_from_env", lambda **_k: SimpleNamespace())

    app = Flask("auth-disabled-auth0")
    runtime = module.bootstrap_runtime(app, config_path="/fake/config.json")

    assert runtime.auth0_mgmt_client is None
    assert app.config.get("SERVICE_TOKENS") is None


def test_bootstrap_runtime_logs_provisioning_failure(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    """Provisioning failures should be logged and leave optional service unset."""

    module = _reload_module(monkeypatch)

    auth_config = SimpleNamespace(
        auth_enabled=True,
        org_signup_v2_enabled=True,
        device_rbac_enforcement=True,
        use_firestore_auth=False,
        use_firestore_audit=False,
        provisioning_jwt_ttl_seconds=30,
        auth0_webhook_secret=None,
    )
    monkeypatch.setattr(module.AuthConfig, "from_file", classmethod(lambda cls, _path: auth_config))

    server_config = SimpleNamespace(
        rate_limit=SimpleNamespace(global_limit=1),
        breaker=SimpleNamespace(failure_threshold=5, window_seconds=10, half_open_after_seconds=5),
        auth0_mgmt=SimpleNamespace(domain="auth0.local", enabled=True),
    )
    monkeypatch.setattr(module, "get_server_config", lambda: server_config)

    monkeypatch.setattr(module, "AtomicRateLimitConfig", lambda cfg: SimpleNamespace(config=cfg))
    monkeypatch.setattr(module, "UserManager", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "SessionManager", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "AuditLogger", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "RateLimiter", lambda *a, **k: SimpleNamespace())

    class _EnabledAuth0Client:
        def __init__(self, *_a, **_k):
            self.enabled = True

    monkeypatch.setattr(module, "Auth0ManagementClient", _EnabledAuth0Client)
    monkeypatch.setattr(module, "load_replay_cache_from_env", lambda **_k: SimpleNamespace(_redis=True))
    monkeypatch.setattr(module, "_build_service_token_settings", lambda: SimpleNamespace(
        keyset=SimpleNamespace(),
        audience="aud",
        issuer="iss",
        required_scopes=("scope",),
    ))

    class _FailingProvisioningService:
        def __init__(self, *_args, **_kwargs):
            raise module.ServiceConfigurationError("invalid provisioning config")

    monkeypatch.setattr(module, "ProvisioningTokenService", _FailingProvisioningService)
    monkeypatch.setattr(module, "InviteService", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(module, "EmailVerificationService", lambda *a, **k: SimpleNamespace())

    caplog.set_level("ERROR")

    app = Flask("auth-provisioning-failure")
    runtime = module.bootstrap_runtime(app, config_path="/fake/config.json")

    assert runtime.provisioning_service is None
    assert runtime.invite_service is not None
    assert any("Provisioning service initialization failed" in record.message for record in caplog.records)

