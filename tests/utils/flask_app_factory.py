"""Helpers for building stateless Flask app factories in tests."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Iterator, Mapping, MutableMapping

from flask import Flask

from .flask_client_factory import apply_config_overrides, flask_test_client, set_default_context


def build_flask_app(
    builder: Callable[[], Flask],
    *,
    config_overrides: Mapping[str, object] | None = None,
    base_context: MutableMapping[str, object] | None = None,
) -> Flask:
    """Materialise a Flask app with optional overrides and context seeding."""

    app = builder()
    apply_config_overrides(app, config_overrides)
    set_default_context(app, base_context)
    return app


def assert_stateless_app_factory(
    builder: Callable[..., Flask],
    *,
    marker_key: str = "__stateless_probe__",
) -> None:
    """Ensure the provided factory returns fresh app instances on each call."""

    first = builder()
    first.config[marker_key] = object()

    second = builder()
    if second is first:
        raise AssertionError("Flask app factory returned the same instance on consecutive calls")
    if second.config.get(marker_key) is first.config[marker_key]:
        raise AssertionError("Flask app factory leaked configuration state between instances")


@contextmanager
def stateless_test_client(
    builder: Callable[..., Flask],
    *,
    config_overrides: Mapping[str, object] | None = None,
    base_context: MutableMapping[str, object] | None = None,
    dependency_overrides: Mapping[Any, Mapping[str, Any]] | None = None,
) -> Iterator[tuple[Flask, Any]]:
    """Yield a Flask test client after asserting stateless factory behaviour."""

    assert_stateless_app_factory(builder)
    with flask_test_client(
        lambda: build_flask_app(builder, config_overrides=config_overrides, base_context=base_context),
        dependency_overrides=dependency_overrides,
    ) as ctx:
        yield ctx


