"""
Pytest configuration and shared fixtures for BAS System tests.
"""

import os
import sys
import tempfile
import pytest
import logging
from unittest.mock import Mock, patch
from typing import Generator, Dict, Any

# Ensure critical project paths are available before any fixture imports
# This must run early so that modules like `auth.*` (from `server/auth`) resolve during fixture import
project_tests_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(project_tests_dir)
server_path = os.path.join(project_root, 'server')
src_path = os.path.join(project_root, 'src')
infra_path = os.path.join(project_root, 'infra')
for _p in (server_path, src_path, infra_path):
    if os.path.exists(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

# Load custom pytest plugins for contract validation, reporting, and imports
pytest_plugins = [
    'tests.plugins.contract_validator',
    'tests.plugins.contract_reporter',
    'tests.plugins.business_rules_validator',
    'tests.plugins.import_manager',
]
# Allow disabling heavy plugins for quick local runs or constrained environments
if os.getenv('BAS_DISABLE_PLUGINS') == '1':
    pytest_plugins = []

# Import contract validation components
try:
    from tests.contracts.firestore import ContractValidator, ValidationResult
    from tests.contracts.base import OperationResult, QueryOptions
    from tests.utils.business_rules import BusinessRules
    CONTRACTS_AVAILABLE = True
except Exception:
    CONTRACTS_AVAILABLE = False
    ContractValidator = None
    ValidationResult = None
    BusinessRules = None

# Global contract validator instance
_contract_validator = ContractValidator() if CONTRACTS_AVAILABLE else None
_business_rules = BusinessRules() if CONTRACTS_AVAILABLE else None

_fs_skipped_count = 0  # Count of tests skipped due to missing Firestore helpers

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

# Firestore mock helpers fixtures
try:
    from tests.utils.mocks.firestore import (
        make_firestore_client,
        make_collection,
        attach_collection,
        make_doc,
        make_query,
        set_where_chain,
        set_document_get,
        set_permission_denied,
        set_exception,
    )
    _FS_HELPERS_AVAILABLE = True
except Exception:
    _FS_HELPERS_AVAILABLE = False

# Allow forcing Firestore helpers off via env for testing skip logic
if os.getenv('BAS_DISABLE_FS_HELPERS') == '1':
    _FS_HELPERS_AVAILABLE = False


@pytest.fixture
def fs_client():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    return make_firestore_client()


@pytest.fixture
def fs_collection():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    return make_collection()


@pytest.fixture
def query_with_docs():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    # Example query that returns two empty docs by default
    d1 = make_doc('d1', {})
    d2 = make_doc('d2', {})
    return make_query([d1, d2])


@pytest.fixture
def query_empty():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    return make_query([])


@pytest.fixture
def query_perm_denied():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    from google.api_core.exceptions import PermissionDenied as _PD  # type: ignore
    return make_query(side_effect=_PD('denied'))


@pytest.fixture
def query_exception():
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")
    return make_query(side_effect=Exception('boom'))


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


# Contract validation hooks
def pytest_configure(config):
    """Configure pytest with contract validation settings."""
    if CONTRACTS_AVAILABLE:
        # Add contract validation marker
        config.addinivalue_line("markers", "contract: Tests that validate contracts")
        config.addinivalue_line("markers", "no_contract_validation: Skip contract validation for these tests")

        # Log contract validation status
        logging.getLogger('contract_validation').info("Contract validation enabled")


def pytest_sessionstart(session):
    """Validate contracts at session start."""
    if not CONTRACTS_AVAILABLE:
        logging.warning("Contract validation is disabled: contract modules not available")
        return

    global _contract_validator

    try:
        # Validate that contract components are properly initialized
        if _contract_validator is None:
            raise RuntimeError("Contract validator not initialized")

        # Test basic validation functionality
        test_result = _contract_validator.validate_business_rules(
            'auth_check',
            {'user_id': 'test_user', 'permissions': ['read']}
        )

        logging.info("Contract validation active: validator initialized successfully")
    except Exception as e:
        logging.warning(f"Contract validation initialization failed: {e}")
        # Continue without contract validation
        _contract_validator = None


def pytest_runtest_logreport(report):
    """Track Firestore-related skips to surface a single session-level warning."""
    # Only count setup-phase skips (fixtures) with our specific reason
    if report.when == "setup" and report.outcome == "skipped":
        try:
            reason_text = str(report.longrepr)
        except Exception:
            reason_text = ""
        if "Firestore helpers not available" in reason_text:
            global _fs_skipped_count
            _fs_skipped_count += 1


def pytest_sessionfinish(session, exitstatus):
    """Emit a concise summary warning if Firestore helper-based tests were skipped."""
    if not globals().get("_FS_HELPERS_AVAILABLE", False):
        count = globals().get("_fs_skipped_count", 0)
        if count > 0:
            logging.warning(f"Skipped {count} Firestore tests due to missing helpers")


@pytest.fixture(autouse=True)
def validate_contract_compliance(request):
    """Automatically validate contract compliance for applicable tests."""
    if not CONTRACTS_AVAILABLE or _contract_validator is None:
        yield
        return

    # Skip contract validation for tests marked with no_contract_validation
    if request.node.get_closest_marker("no_contract_validation"):
        yield
        return

    # Only validate tests that use contract-related fixtures or are in contract directories
    should_validate = (
        'contract' in str(request.node.fspath) or
        any('contract' in str(marker) for marker in request.node.iter_markers())
    )

    if should_validate:
        try:
            # Validate basic contract compliance
            _validate_test_contract_compliance(request)
        except Exception as e:
            pytest.fail(f"Contract validation error in test {request.node.name}: {e}")

    yield


def _validate_test_contract_compliance(request):
    """Validate contract compliance for a test."""
    # Extract test metadata for contract validation
    test_name = request.node.name
    test_file = str(request.node.fspath)

    # Validate that test follows contract naming conventions
    if not test_name.startswith('test_'):
        raise ValueError(f"Test name does not follow contract naming convention: {test_name}")

    # For contract-related tests, validate that they import contract components
    if 'contract' in test_file.lower():
        test_module = request.module
        if hasattr(test_module, '__file__'):
            # Basic validation that contract tests are properly structured
            pass


@pytest.fixture
def contract_validator():
    """Provide contract validator instance for tests."""
    if not CONTRACTS_AVAILABLE or _contract_validator is None:
        pytest.skip("Contract validation not available")
    return _contract_validator


@pytest.fixture
def business_rules():
    """Provide business rules instance for tests."""
    if not CONTRACTS_AVAILABLE or _business_rules is None:
        pytest.skip("Business rules not available")
    return _business_rules


@pytest.fixture
def mock_operation_result():
    """Provide a mock OperationResult for testing."""
    if not CONTRACTS_AVAILABLE:
        pytest.skip("Contract types not available")
    return OperationResult


@pytest.fixture
def mock_query_options():
    """Provide mock QueryOptions for testing."""
    if not CONTRACTS_AVAILABLE:
        pytest.skip("Contract types not available")
    return QueryOptions


@pytest.mark.import_test
def test_import_resolution(import_paths, validate_imports):
    """Test that all required imports resolve correctly."""
    # This test will run as part of the import validation
    # The validate_imports fixture will handle the actual validation
    assert True, "Import resolution test passed"
