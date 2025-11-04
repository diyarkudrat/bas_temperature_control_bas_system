"""Auth service fixtures to support unit tests."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.utils.flask_client_factory import flask_test_client


def _reload_auth_module():
    module = importlib.import_module("apps.auth_service.main")
    return importlib.reload(module)


def _fake_runtime(module):
    runtime = module.AuthRuntime(
        config=SimpleNamespace(
            auth_enabled=True,
            org_signup_v2_enabled=False,
            device_rbac_enforcement=False,
        ),
        server_config=SimpleNamespace(rate_limit=SimpleNamespace(), breaker=SimpleNamespace()),
        rate_limit_holder=SimpleNamespace(reset=lambda: None),
        user_manager=Mock(name="user_manager"),
        session_manager=Mock(name="session_manager"),
        audit_logger=Mock(name="audit_logger"),
        rate_limiter=Mock(name="rate_limiter"),
        firestore_factory=None,
        service_tokens=None,
        http_session=Mock(name="http_session"),
        provisioning_service=None,
        invite_service=None,
        verification_service=None,
        auth0_mgmt_client=None,
    )
    return runtime


@pytest.fixture
def auth_module(monkeypatch):
    module = _reload_auth_module()

    fake_runtime = _fake_runtime(module)

    def _bootstrap_runtime(app, *, config_path=None):
        app.config.setdefault("AUTH_SERVICE_RUNTIME", fake_runtime)
        return fake_runtime

    monkeypatch.setattr(module, "bootstrap_runtime", _bootstrap_runtime)
    monkeypatch.setattr(module, "register_healthcheck", lambda app, runtime: None)
    monkeypatch.setattr(module, "_register_request_hooks", lambda app, runtime: None)
    monkeypatch.setattr(module, "_register_blueprints", lambda app: None)

    return module


@pytest.fixture
def auth_app(auth_module):
    app = auth_module.create_app()
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def auth_client(auth_app):
    with flask_test_client(lambda: auth_app) as (_, client):
        yield client


