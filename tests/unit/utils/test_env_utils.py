"""Unit tests for environment utility helpers."""

from __future__ import annotations

import os

from tests.utils import env as env_utils


def test_patched_env_restores_original_values():
    original = os.environ.get("BAS_TEST_VAR")
    with env_utils.patched_env({"BAS_TEST_VAR": "patched", "BAS_TEST_REMOVE": None}):
        assert os.environ.get("BAS_TEST_VAR") == "patched"
        assert "BAS_TEST_REMOVE" not in os.environ

    assert os.environ.get("BAS_TEST_VAR") == original
    assert "BAS_TEST_REMOVE" not in os.environ


def test_environment_defaults_only_apply_when_missing(monkeypatch):
    monkeypatch.delenv("BAS_DEFAULT_ONLY", raising=False)
    with env_utils.environment(defaults={"BAS_DEFAULT_ONLY": "fallback"}):
        assert os.environ["BAS_DEFAULT_ONLY"] == "fallback"
    assert "BAS_DEFAULT_ONLY" not in os.environ


def test_env_flag_handles_boolean_values(monkeypatch):
    monkeypatch.setenv("BAS_FLAG_TRUE", "yes")
    monkeypatch.setenv("BAS_FLAG_FALSE", "0")
    assert env_utils.env_flag("BAS_FLAG_TRUE") is True
    assert env_utils.env_flag("BAS_FLAG_FALSE", default=True) is False
    assert env_utils.env_flag("BAS_FLAG_MISSING", default=True) is True

