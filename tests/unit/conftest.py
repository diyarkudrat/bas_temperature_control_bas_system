"""Lightweight fixtures for unit-test suites."""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest
from unittest.mock import Mock


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


