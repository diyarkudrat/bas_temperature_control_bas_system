"""Fixtures for logging library unit tests."""

from __future__ import annotations

import importlib

import pytest

from logging_lib import get_logger
from logging_lib.logger import LoggerManager

from tests.utils.logging import reset_logging_metrics


@pytest.fixture(autouse=True)
def _reset_logging_metrics():
    reset_logging_metrics()
    yield
    reset_logging_metrics()


@pytest.fixture
def logger_manager(monkeypatch):
    module = importlib.import_module("logging_lib.logger")
    manager = LoggerManager()
    monkeypatch.setattr(module, "_LOGGER_MANAGER", manager, raising=False)
    return manager


@pytest.fixture
def memory_logger(logger_manager):
    logger_manager.configure(logger_manager.settings)
    return get_logger("memory-test")


