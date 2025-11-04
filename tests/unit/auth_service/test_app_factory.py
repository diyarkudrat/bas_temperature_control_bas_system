"""Tests covering the auth service Flask application factory."""

from __future__ import annotations

import importlib
import logging
import sys
from types import SimpleNamespace
from typing import Any, List, Tuple

import pytest
from flask import Flask, Request

from tests.utils.flask_app_factory import assert_stateless_app_factory


class _StubLogger:
    """Minimal structured logger test double."""

    def __init__(self, name: str, call_log: List[Tuple[str, str, str]]) -> None:
        self._name = name
        self._calls = call_log

    def info(self, message: str, **fields: Any) -> None:
        self._calls.append((self._name, "info", message))

    def debug(self, message: str, **fields: Any) -> None:  # pragma: no cover - debug not asserted
        self._calls.append((self._name, "debug", message))

    def warning(self, message: str, **fields: Any) -> None:  # pragma: no cover - defensive
        self._calls.append((self._name, "warning", message))


def _reload_module(monkeypatch: pytest.MonkeyPatch):
    """Reload the auth service module with deterministic dependencies."""

    module_name = "apps.auth_service.main"
    sys.modules.pop(module_name, None)

    # Prevent the real global logging bootstrap from running during import.
    monkeypatch.setattr(logging, "basicConfig", lambda **_kwargs: None)

    module = importlib.import_module(module_name)
    return module


def test_create_app_stateless_and_invokes_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    """`create_app` should build fresh Flask instances and wire helpers."""

    module = _reload_module(monkeypatch)

    log_calls: List[Tuple[str, str, str]] = []
    monkeypatch.setattr(module, "configure_structured_logging", lambda **_kwargs: None)
    monkeypatch.setattr(module, "get_structured_logger", lambda name: _StubLogger(name, log_calls))
    module.logger = _StubLogger("auth.main", log_calls)
    module.service_token_logger = _StubLogger("auth.service_tokens", log_calls)

    runtimes: List[SimpleNamespace] = []
    registration_calls: List[Tuple[str, Flask, object]] = []
    context_calls: List[Tuple[Flask, str]] = []

    def _fake_runtime(app: Flask, *, config_path: str | None = None) -> SimpleNamespace:
        runtime = SimpleNamespace(app=app, config=SimpleNamespace(), server_config=SimpleNamespace())
        runtimes.append(runtime)
        return runtime

    def _register_healthcheck(app: Flask, runtime: object) -> None:
        registration_calls.append(("health", app, runtime))

    def _register_hooks(app: Flask, runtime: object) -> None:
        registration_calls.append(("hooks", app, runtime))

    def _register_blueprints(app: Flask) -> None:
        registration_calls.append(("blueprints", app, None))

    monkeypatch.setattr(module, "bootstrap_runtime", _fake_runtime)
    monkeypatch.setattr(module, "register_healthcheck", _register_healthcheck)
    monkeypatch.setattr(module, "_register_request_hooks", _register_hooks)
    monkeypatch.setattr(module, "_register_blueprints", _register_blueprints)
    monkeypatch.setattr(module, "register_flask_context", lambda app, service: context_calls.append((app, service)))

    def _factory() -> Flask:
        return module.create_app(config_path="test-config.json")

    assert_stateless_app_factory(_factory)

    app = _factory()
    assert isinstance(app, Flask)

    # Validate lifecycle calls for the produced app instance.
    assert context_calls == [(app, "auth")]

    assert {call[0] for call in registration_calls} == {"health", "hooks", "blueprints"}
    assert all(call[1] is app for call in registration_calls)
    assert runtimes and all(call[2] is runtimes[0] or call[2] is None for call in registration_calls)


def test_register_request_hooks_attaches_runtime_to_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """The before-request hook should expose runtime dependencies on the request."""

    module = _reload_module(monkeypatch)

    runtime = SimpleNamespace(
        config="cfg",
        server_config="server",
        rate_limit_holder="rate-limit",
        session_manager="session",
        audit_logger="audit",
        rate_limiter="rate",
        user_manager="user",
        firestore_factory="firestore",
        service_tokens="service-tokens",
        provisioning_service="provisioning",
        invite_service="invite",
        verification_service="verification",
        auth0_mgmt_client="auth0",
    )

    app = Flask("auth-test")
    module._register_request_hooks(app, runtime)

    hooks = app.before_request_funcs.get(None, [])
    assert hooks, "Expected a before_request hook to be registered"

    hook = hooks[0]

    with app.test_request_context("/healthz") as ctx:
        hook()
        request: Request = ctx.request
        assert request.auth_config == "cfg"
        assert request.server_config == "server"
        assert request.rate_limit_holder == "rate-limit"
        assert request.session_manager == "session"
        assert request.audit_logger == "audit"
        assert request.rate_limiter == "rate"
        assert request.user_manager == "user"
        assert request.firestore_factory == "firestore"
        assert request.service_tokens == "service-tokens"
        assert request.provisioning_service == "provisioning"
        assert request.invite_service == "invite"
        assert request.verification_service == "verification"
        assert request.auth0_mgmt_client == "auth0"


