"""Legacy contract validation fixtures maintained for compatibility."""

from __future__ import annotations

import logging
from typing import Any

import pytest

try:  # pragma: no cover - optional dependency surface
    from tests.contracts.base import OperationResult, QueryOptions
    from tests.contracts.firestore import ContractValidator, ValidationResult
    from tests.utils.business_rules import BusinessRules

    CONTRACTS_AVAILABLE = True
except Exception:  # pragma: no cover - executed when deps absent
    CONTRACTS_AVAILABLE = False
    ContractValidator = None  # type: ignore[assignment]
    ValidationResult = None  # type: ignore[assignment]
    BusinessRules = None  # type: ignore[assignment]
    OperationResult = None  # type: ignore[assignment]
    QueryOptions = None  # type: ignore[assignment]


_contract_validator = ContractValidator() if CONTRACTS_AVAILABLE else None
_business_rules = BusinessRules() if CONTRACTS_AVAILABLE else None
_fs_skipped_count = 0


def pytest_configure(config):  # pragma: no cover - configuration hook
    if not CONTRACTS_AVAILABLE:
        logging.getLogger("contract_validation").info("Contract validation disabled: modules unavailable")
        return

    config.addinivalue_line("markers", "contract: Tests that validate contracts")
    config.addinivalue_line("markers", "no_contract_validation: Skip contract validation for these tests")
    logging.getLogger("contract_validation").info("Contract validation enabled")


def pytest_sessionstart(session):  # pragma: no cover - configuration hook
    if not CONTRACTS_AVAILABLE:
        logging.warning("Contract validation is disabled: contract modules not available")
        return

    global _contract_validator

    try:
        if _contract_validator is None:
            raise RuntimeError("Contract validator not initialized")

        _contract_validator.validate_business_rules(  # smoke validation
            "auth_check",
            {"user_id": "test_user", "permissions": ["read"]},
        )
        logging.info("Contract validation active: validator initialized successfully")
    except Exception as exc:
        logging.warning("Contract validation initialization failed: %s", exc)
        _contract_validator = None


def pytest_runtest_logreport(report):  # pragma: no cover - runtime hook
    if report.when != "setup" or report.outcome != "skipped":
        return

    try:
        reason_text = str(report.longrepr)
    except Exception:  # pragma: no cover - defensive path
        reason_text = ""

    if "Firestore helpers not available" in reason_text:
        global _fs_skipped_count
        _fs_skipped_count += 1


def pytest_sessionfinish(session, exitstatus):  # pragma: no cover - runtime hook
    if _fs_skipped_count > 0:
        logging.warning("Skipped %s Firestore tests due to missing helpers", _fs_skipped_count)


@pytest.fixture(autouse=True)
def validate_contract_compliance(request):
    if not CONTRACTS_AVAILABLE or _contract_validator is None:
        yield
        return

    if request.node.get_closest_marker("no_contract_validation"):
        yield
        return

    should_validate = "contract" in str(request.node.fspath) or any(
        "contract" in marker.name for marker in request.node.iter_markers()
    )

    if should_validate:
        try:
            _validate_test_contract_compliance(request)
        except Exception as exc:
            pytest.fail(f"Contract validation error in test {request.node.name}: {exc}")

    yield


def _validate_test_contract_compliance(request: pytest.FixtureRequest) -> None:
    test_name = request.node.name
    if not test_name.startswith("test_"):
        raise ValueError(f"Test name does not follow contract naming convention: {test_name}")


@pytest.fixture
def contract_validator():
    if not CONTRACTS_AVAILABLE or _contract_validator is None:
        pytest.skip("Contract validation not available")
    return _contract_validator


@pytest.fixture
def business_rules():
    if not CONTRACTS_AVAILABLE or _business_rules is None:
        pytest.skip("Business rules not available")
    return _business_rules


@pytest.fixture
def mock_operation_result():
    if not CONTRACTS_AVAILABLE or OperationResult is None:
        pytest.skip("Contract types not available")
    return OperationResult


@pytest.fixture
def mock_query_options():
    if not CONTRACTS_AVAILABLE or QueryOptions is None:
        pytest.skip("Contract types not available")
    return QueryOptions


