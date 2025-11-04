"""Unit tests for Flask app factory helpers."""

from __future__ import annotations

from flask import Flask

from tests.utils.flask_app_factory import (
    assert_stateless_app_factory,
    stateless_test_client,
)


def _builder() -> Flask:
    app = Flask("test_app_factory")
    app.config.update(TESTING=True)
    return app


def test_assert_stateless_app_factory_detects_leaks():
    assert_stateless_app_factory(_builder)


def test_stateless_test_client_creates_isolated_clients():
    with stateless_test_client(_builder) as (app, client):
        assert app.config["TESTING"] is True
        response = client.get("/")
        assert response.status_code == 404

