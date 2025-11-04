"""Helpers for building Flask test clients with explicit dependency overrides."""

from __future__ import annotations

import importlib
from contextlib import ExitStack, contextmanager
from typing import Any, Callable, Iterator, Mapping, MutableMapping

from flask import Flask


def load_flask_app(module_path: str, factory_attr: str = "create_app", **factory_kwargs: Any) -> Flask:
    """Import a module and return a Flask application instance.

    Prefers a factory named ``factory_attr`` when available. Falls back to a module-level
    ``app`` attribute. Raises ``ValueError`` if no application can be produced.
    """

    module = importlib.import_module(module_path)

    if hasattr(module, factory_attr):
        factory = getattr(module, factory_attr)
        if callable(factory):
            app = factory(**factory_kwargs)
            if isinstance(app, Flask):
                return app
            raise ValueError(f"{module_path}.{factory_attr} did not return a Flask app")

    if hasattr(module, "app"):
        app = getattr(module, "app")
        if isinstance(app, Flask):
            return app

    raise ValueError(f"Module {module_path} does not expose a Flask app or factory")


def apply_config_overrides(app: Flask, overrides: Mapping[str, Any] | None = None) -> Flask:
    """Apply config overrides to an app and return it for chaining."""

    if overrides:
        for key, value in overrides.items():
            app.config[key] = value
    return app


@contextmanager
def override_dependencies(target: Any, overrides: Mapping[str, Any]):
    """Temporarily override attributes on a target object."""

    sentinel = object()
    original: dict[str, Any] = {}

    for attr, replacement in overrides.items():
        original[attr] = getattr(target, attr, sentinel)
        setattr(target, attr, replacement)

    try:
        yield target
    finally:
        for attr, previous in original.items():
            if previous is sentinel:
                delattr(target, attr)
            else:
                setattr(target, attr, previous)


@contextmanager
def flask_test_client(
    app_builder: Callable[[], Flask],
    *,
    config_overrides: Mapping[str, Any] | None = None,
    dependency_overrides: Mapping[Any, Mapping[str, Any]] | None = None,
) -> Iterator[tuple[Flask, Any]]:
    """Provide a Flask test client with optional config and dependency overrides."""

    app = app_builder()
    apply_config_overrides(app, config_overrides)

    with ExitStack() as stack:
        if dependency_overrides:
            for target, overrides in dependency_overrides.items():
                stack.enter_context(override_dependencies(target, overrides))

        client_cm = stack.enter_context(app.test_client())
        yield app, client_cm


def set_default_context(app: Flask, base_context: MutableMapping[str, Any] | None = None) -> None:
    """Store reusable context defaults on the Flask app for later assertions."""

    if base_context is not None:
        app.config.setdefault("test_base_context", dict(base_context))


