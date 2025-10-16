"""
Pytest configuration and shared fixtures for BAS System tests.
"""

import os
import sys
import tempfile
import pytest
from unittest.mock import Mock, patch
from typing import Generator

# Add project directories to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
server_path = os.path.join(project_root, 'server')

if server_path not in sys.path:
    sys.path.insert(0, server_path)


@pytest.fixture
def temp_db_file() -> Generator[str, None, None]:
    """Provide a temporary database file for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    temp_file.close()
    yield temp_file.name
    # Cleanup
    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_config_file() -> Generator[str, None, None]:
    """Provide a temporary config file for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
    temp_file.close()
    yield temp_file.name
    # Cleanup
    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.fixture
def mock_request():
    """Provide a mock Flask request object."""
    request = Mock()
    request.headers = {
        'User-Agent': 'Mozilla/5.0 (Test Browser)',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate'
    }
    request.remote_addr = '192.168.1.100'
    request.endpoint = 'test_endpoint'
    return request


@pytest.fixture
def mock_twilio_client():
    """Provide a mock Twilio client for SMS testing."""
    client = Mock()
    message = Mock()
    message.sid = "test_message_sid"
    client.messages.create.return_value = message
    return client


# Test markers for categorization
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "auth: Authentication related tests")
    config.addinivalue_line("markers", "slow: Slow running tests")


# Import all fixtures
from tests.fixtures.auth_fixtures import *


# Pytest configuration
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add default markers."""
    for item in items:
        # Add unit marker by default if no other marker is present
        if not any(marker.name in ['integration', 'performance'] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)
        
        # Add domain markers based on file path
        if 'auth' in str(item.fspath):
            item.add_marker(pytest.mark.auth)
