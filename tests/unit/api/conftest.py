"""API service specific fixtures for unit tests."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.utils.flask_client_factory import flask_test_client


def _reload_api_module():
    module = importlib.import_module("apps.api.main")
    return importlib.reload(module)


@pytest.fixture
def api_module(monkeypatch):
    module = _reload_api_module()

    module.auth_provider = Mock(name="auth_provider")
    module.auth_metrics = Mock(name="auth_metrics")
    module.auth_service_client_factory = lambda: Mock(name="auth_service_client")
    module.firestore_factory = Mock(name="firestore_factory")
    module.tenant_middleware = Mock(name="tenant_middleware")
    module.app.config.update(TESTING=True)
    module.app.config.setdefault("rate_limit_holder", SimpleNamespace(reset=lambda: None))
    return module


@pytest.fixture
def api_app(api_module):
    return api_module.app


@pytest.fixture
def api_client(api_app):
    with flask_test_client(lambda: api_app) as (_, client):
        yield client


