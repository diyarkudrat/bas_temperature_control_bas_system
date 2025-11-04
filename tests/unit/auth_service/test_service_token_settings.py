"""Tests for auth service service token configuration helpers."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import pytest

from app_platform.security import ServiceTokenError

from tests.utils.env import environment


def _reload_module(monkeypatch: pytest.MonkeyPatch):
    module_name = "apps.auth_service.main"
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


class _StubLogger:
    """Capture structured log invocations for assertions."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def info(self, message: str, *, extra: Dict[str, Any] | None = None, exc_info: Any | None = None) -> None:
        self.calls.append(("info", message, extra or {}))

    def error(self, message: str, *, extra: Dict[str, Any] | None = None, exc_info: Any | None = None) -> None:
        self.calls.append(("error", message, extra or {}))


def test_build_service_token_settings_parses_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables should determine issuer, audience, and scopes."""

    module = _reload_module(monkeypatch)

    keyset = SimpleNamespace(keys=[SimpleNamespace(kid="kid-a"), SimpleNamespace(kid="kid-b")], default_kid="kid-a")
    monkeypatch.setattr(module, "load_service_keyset_from_env", lambda prefix: keyset)

    replay_calls: List[Dict[str, Any]] = []

    def _fake_replay_cache(*, prefix: str, namespace: str, **kwargs) -> SimpleNamespace:
        payload = {"prefix": prefix, "namespace": namespace, **kwargs}
        replay_calls.append(payload)
        sentinel = SimpleNamespace(**payload)
        sentinel._redis = object()
        return sentinel

    monkeypatch.setattr(module, "load_replay_cache_from_env", _fake_replay_cache)

    logger_stub = _StubLogger()
    module.service_token_logger = logger_stub

    with environment(
        overrides={
            "SERVICE_JWT_PREFIX": "SERVICE_AUTH",
            "SERVICE_JWT_EXPECTED_AUDIENCE": "api://auth",
            "SERVICE_JWT_EXPECTED_ISSUER": "issuer://auth",
            "SERVICE_JWT_ALLOWED_SUBJECTS": " svc-api , svc-gateway ",
            "SERVICE_JWT_REQUIRED_SCOPES": "auth.update,auth.write",
        },
        defaults={"AUTH0_DOMAIN": "acme.auth0.local"},
    ):
        settings = module._build_service_token_settings()

    assert settings.audience == "api://auth"
    assert settings.issuer == "issuer://auth"
    assert settings.allowed_subjects == ("svc-api", "svc-gateway")
    assert settings.required_scopes == ("auth.update", "auth.write")
    assert settings.keyset is keyset

    assert replay_calls == [{"prefix": "SERVICE_AUTH", "namespace": "auth-service"}]

    info_messages = [entry for entry in logger_stub.calls if entry[0] == "info"]
    assert any(entry[1] == "Replay cache initialized" for entry in info_messages)
    assert any("Service JWT verifier configured" in entry[1] for entry in info_messages)


def test_build_service_token_settings_raises_on_keyset_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keyset loader failures should surface as configuration errors."""

    module = _reload_module(monkeypatch)

    def _fail_loader(*_args, **_kwargs):
        raise ServiceTokenError("missing keyset")

    monkeypatch.setattr(module, "load_service_keyset_from_env", _fail_loader)
    module.service_token_logger = _StubLogger()

    with pytest.raises(RuntimeError):
        module._build_service_token_settings()

    error_calls = [entry for entry in module.service_token_logger.calls if entry[0] == "error"]
    assert error_calls, "Expected error log when keyset loading fails"


