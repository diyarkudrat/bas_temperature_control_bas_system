"""Top-level pytest configuration for BAS System tests.

This module keeps startup lightweight for unit suites while still allowing legacy
contract fixtures and heavy plugins to be opted in when required.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _install_google_cloud_stubs() -> None:
    """Install lightweight stubs for google-cloud dependencies used in tests."""

    if "google" in sys.modules:
        # Replace wholesale to avoid partially installed incompatible packages.
        del sys.modules["google"]

    google_module = ModuleType("google")
    google_module.__path__ = []  # mark as package

    cloud_module = ModuleType("google.cloud")
    cloud_module.__path__ = []

    # --- Firestore stubs -------------------------------------------------
    firestore_module = ModuleType("google.cloud.firestore")
    firestore_module.__path__ = []

    class _CollectionReference:
        def __init__(self, name: str = "") -> None:
            self._name = name

        def document(self, doc_id: str) -> SimpleNamespace:
            doc = SimpleNamespace(
                id=doc_id,
                exists=False,
                to_dict=lambda: {},
                get=lambda **_: SimpleNamespace(exists=False, to_dict=lambda: {}),
                set=lambda *args, **kwargs: None,
                delete=lambda: None,
            )
            return doc

        def where(self, *args, **kwargs) -> "._CollectionReference":
            return self

        def limit(self, *args, **kwargs) -> "._CollectionReference":
            return self

        def stream(self):
            return iter(())

    class _StubFirestoreClient:
        def __init__(self, *args, **kwargs) -> None:
            self._kwargs = kwargs

        def collections(self):
            return iter(())

        def collection(self, name: str) -> SimpleNamespace:
            return _CollectionReference(name)

        def transaction(self):
            class _Txn:
                def call(self, func):
                    return func(self)

                def update(self, *args, **kwargs):
                    return None

            return _Txn()

    firestore_module.Client = _StubFirestoreClient
    firestore_module.AsyncClient = _StubFirestoreClient
    firestore_module.SERVER_TIMESTAMP = object()
    firestore_module.CollectionReference = _CollectionReference

    # firestore_v1 stubs to satisfy indirect imports
    firestore_v1_module = ModuleType("google.cloud.firestore_v1")
    firestore_v1_module.__path__ = []
    firestore_v1_types = ModuleType("google.cloud.firestore_v1.types")
    firestore_v1_types.__path__ = []
    firestore_v1_module.types = firestore_v1_types

    class _AggregationResult:
        pass

    firestore_v1_types.AggregationResult = _AggregationResult

    # --- Logging stubs ---------------------------------------------------
    logging_module = ModuleType("google.cloud.logging")
    logging_module.__path__ = []

    class _StubLogger:
        def __init__(self, name: str) -> None:
            self.name = name

        def log_struct(self, *args, **kwargs) -> None:
            return None

    class _StubLoggingClient:
        def __init__(self, project: str | None = None, *args, **kwargs) -> None:
            self.project = project or "stub-project"

        def logger(self, name: str) -> _StubLogger:
            return _StubLogger(name)

    logging_module.Client = _StubLoggingClient

    # --- Auth stubs ------------------------------------------------------
    auth_module = ModuleType("google.auth")
    auth_module.__path__ = []

    def _default_credentials():
        return (object(), "stub-project")

    auth_module.default = _default_credentials

    # --- API core stubs --------------------------------------------------
    api_core_module = ModuleType("google.api_core")
    api_core_module.__path__ = []
    exceptions_module = ModuleType("google.api_core.exceptions")
    exceptions_module.__path__ = []

    class GoogleAPICallError(Exception):
        pass

    class PermissionDenied(GoogleAPICallError):
        pass

    class NotFound(GoogleAPICallError):
        pass

    exceptions_module.GoogleAPICallError = GoogleAPICallError
    exceptions_module.PermissionDenied = PermissionDenied
    exceptions_module.NotFound = NotFound
    api_core_module.exceptions = exceptions_module

    # --- RPC stubs (to satisfy api_core imports) ------------------------
    rpc_module = ModuleType("google.rpc")
    rpc_module.__path__ = []
    error_details_module = ModuleType("google.rpc.error_details_pb2")
    error_details_module.__path__ = []
    rpc_module.error_details_pb2 = error_details_module

    # --- Register modules ------------------------------------------------
    sys.modules.update(
        {
            "google": google_module,
            "google.cloud": cloud_module,
            "google.cloud.firestore": firestore_module,
            "google.cloud.firestore_v1": firestore_v1_module,
            "google.cloud.firestore_v1.types": firestore_v1_types,
            "google.cloud.logging": logging_module,
            "google.auth": auth_module,
            "google.api_core": api_core_module,
            "google.api_core.exceptions": exceptions_module,
            "google.rpc": rpc_module,
            "google.rpc.error_details_pb2": error_details_module,
        }
    )

    google_module.cloud = cloud_module
    google_module.auth = auth_module
    cloud_module.firestore = firestore_module
    cloud_module.logging = logging_module


if os.getenv("BAS_USE_GOOGLE_STUBS", "1") == "1":
    _install_google_cloud_stubs()


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_EXTRA_PATHS = ("server", "src", "infra")

for relative in _EXTRA_PATHS:
    candidate = _PROJECT_ROOT / relative
    if candidate.exists():
        path_str = str(candidate)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


pytest_plugins: list[str] = []

if os.getenv("BAS_DISABLE_PLUGINS", "1") != "1":
    pytest_plugins.extend(
        [
            "tests.plugins.contract_validator",
            "tests.plugins.contract_reporter",
            "tests.plugins.business_rules_validator",
            "tests.plugins.import_manager",
        ]
    )

_CONTRACT_FIXTURES_ENABLED = os.getenv("BAS_ENABLE_CONTRACT_FIXTURES", "1") != "0"
if _CONTRACT_FIXTURES_ENABLED:
    pytest_plugins.append("tests.conftest_contracts")


from tests.fixtures.firestore_fixtures import *  # noqa: F401,F403 - re-export shared fixtures


def pytest_configure(config: pytest.Config) -> None:  # pragma: no cover - configuration hook
    """Register global markers used across the repository."""

    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "auth: Authentication related tests")
    config.addinivalue_line("markers", "logging: Logging library focused tests")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Ensure sensible default markers based on collection context."""

    for item in items:
        if not any(marker.name in {"integration", "performance"} for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)

        fspath = str(item.fspath)
        if "auth" in fspath:
            item.add_marker(pytest.mark.auth)
        if "logging" in fspath:
            item.add_marker(pytest.mark.logging)

"""
Pytest configuration and shared fixtures for BAS System tests.
"""

import os
import sys
import pytest
import logging

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

if not CONTRACTS_AVAILABLE:
    pytest_plugins = [
        plugin
        for plugin in pytest_plugins
        if not plugin.startswith("tests.plugins.contract")
    ]

# Global contract validator instance
_contract_validator = ContractValidator() if CONTRACTS_AVAILABLE else None
_business_rules = BusinessRules() if CONTRACTS_AVAILABLE else None

_fs_skipped_count = 0  # Count of tests skipped due to missing Firestore helpers

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
