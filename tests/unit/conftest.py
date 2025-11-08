"""Common lightweight fixtures shared across unit test suites."""

from __future__ import annotations

import os
import random
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Generator

import pytest
from unittest.mock import Mock


@pytest.fixture(autouse=True)
def _disable_heavy_plugins(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Disable heavyweight pytest plugins unless explicitly enabled."""

    if request.node.get_closest_marker("enable_contract_plugins"):
        return

    monkeypatch.setenv("BAS_DISABLE_PLUGINS", "1")


@pytest.fixture(autouse=True)
def deterministic_random_seed() -> Generator[None, None, None]:
    """Keep Python's RNG deterministic so flaky tests surface quickly."""

    state = random.getstate()
    random.seed(1337)
    yield
    random.setstate(state)


@dataclass
class FrozenClock:
    """Mutable clock helper returned by the ``fake_time`` fixture."""

    epoch: float = 1_700_000_000.0

    def advance(self, seconds: float) -> None:
        self.epoch += seconds

    def time(self) -> float:
        return self.epoch

    def monotonic(self) -> float:
        return self.epoch

    def datetime(self, *, tz: timezone | None = timezone.utc) -> datetime:
        return datetime.fromtimestamp(self.epoch, tz=tz)


@pytest.fixture
def fake_time(monkeypatch: pytest.MonkeyPatch) -> Generator[FrozenClock, None, None]:
    """Provide a mutable time source for tests that assert timestamps."""

    clock = FrozenClock()
    monkeypatch.setattr(time, "time", clock.time)
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    yield clock


@pytest.fixture
def baseline_app_config() -> dict[str, object]:
    """Baseline configuration applied to Flask apps in unit tests."""

    return {
        "TESTING": True,
        "SERVER_NAME": "bas.local",
        "PREFERRED_URL_SCHEME": "http",
    }


@pytest.fixture
def temp_db_file() -> Generator[str, None, None]:
    """Provide a temporary database file for testing."""

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    temp_file.close()
    yield temp_file.name

    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_config_file() -> Generator[str, None, None]:
    """Provide a temporary config file for testing."""

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_file.close()
    yield temp_file.name

    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.fixture
def mock_request() -> Mock:
    """Provide a mock Flask request object."""

    request = Mock()
    request.headers = {
        "User-Agent": "Mozilla/5.0 (Test Browser)",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    request.remote_addr = "192.168.1.100"
    request.endpoint = "test_endpoint"
    return request

