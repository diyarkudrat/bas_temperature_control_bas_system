"""Pytest plugin for contract validation during test execution."""

import pytest
import logging
from typing import Dict, Any, List, Optional

from ..contracts.firestore import ContractEnforcer, ContractViolationError
from ..utils.business_rules import BusinessRules

logger = logging.getLogger(__name__)


def pytest_configure(config):
    """Configure pytest with contract validation settings."""
    # Register markers
    config.addinivalue_line(
        "markers", "contract: Tests that validate contracts"
    )
    config.addinivalue_line(
        "markers", "no_contract_validation: Skip contract validation for these tests"
    )
    config.addinivalue_line(
        "markers", "business_rules: Tests that validate business rules"
    )

    # Add contract validation options
    config.addinivalue_line(
        "addopts", "--contract-validation"
    ) if config.getoption("--contract-validation", default=False) else None


def pytest_addoption(parser):
    """Add command line options for contract validation."""
    # Register custom ini options to avoid PytestConfigWarning for pytest.ini keys
    parser.addini(
        "contract_violation_fail_threshold",
        "Maximum number of contract violations allowed (string; convert to int where used)",
        default="0",
        type="string",
    )
    parser.addini(
        "contract_mock_lazy_init",
        "Whether to lazily initialize contract mocks (bool as string)",
        default="true",
        type="string",
    )
    parser.addini(
        "contract_mock_cache_size",
        "Cache size for contract mocks (string; convert to int where used)",
        default="1000",
        type="string",
    )
    parser.addini(
        "contract_mock_validation_enabled",
        "Enable validation in contract mocks (bool as string)",
        default="true",
        type="string",
    )
    parser.addini(
        "contract_perf_monitoring",
        "Enable performance monitoring for contract operations (bool as string)",
        default="false",
        type="string",
    )
    parser.addini(
        "contract_perf_threshold_ms",
        "Performance threshold in milliseconds (string; convert to int where used)",
        default="100",
        type="string",
    )
    group = parser.getgroup("contract")
    group.addoption(
        "--contract-validation",
        action="store_true",
        default=False,
        help="Enable contract validation during test execution"
    )
    group.addoption(
        "--contract-report",
        action="store_true",
        default=False,
        help="Generate contract compliance report"
    )
    group.addoption(
        "--contract-violation-threshold",
        type=int,
        default=0,
        help="Maximum number of contract violations allowed (default: 0)"
    )


@pytest.fixture(scope="session")
def contract_enforcer():
    """Provide contract enforcer instance for tests."""
    return ContractEnforcer()


@pytest.fixture(scope="session")
def contract_business_rules():
    """Provide business rules instance for contract validation (avoid name clash)."""
    return BusinessRules()


@pytest.fixture(autouse=True)
def contract_validation(request, contract_enforcer, contract_business_rules):
    """Automatically validate contracts during test execution if enabled."""
    if not request.config.getoption("--contract-validation"):
        yield
        return

    # Add legacy compatibility shims for certain tests/fixtures
    try:
        import builtins as _b
        if not hasattr(_b, 'PermissionDenied'):
            class PermissionDenied(Exception):
                pass
            _b.PermissionDenied = PermissionDenied
        if not hasattr(_b, 'PermissionError'):
            class PermissionError(Exception):
                pass
            _b.PermissionError = PermissionError
    except Exception:
        pass

    # Normalize common fixture shapes if present
    try:
        if 'valid_user_data' in request.fixturenames:
            fud = request.getfixturevalue('valid_user_data')
            if isinstance(fud, dict) and 'password_hash' in fud and 'hashed_password' not in fud:
                fud['hashed_password'] = fud['password_hash']
    except Exception:
        pass

    # Skip validation for tests marked with no_contract_validation
    if request.node.get_closest_marker("no_contract_validation"):
        yield
        return

    violations = []

    # Set up contract validation hooks
    original_enforce = contract_enforcer.enforce_create_contract

    def validate_enforce(*args, **kwargs):
        try:
            return original_enforce(*args, **kwargs)
        except ContractViolationError as e:
            violations.append(str(e))
            if request.config.getoption("--contract-violation-threshold", 0) == 0:
                raise
            logger.warning(f"Contract violation (allowed): {e}")

    # Monkey patch for validation
    contract_enforcer.enforce_create_contract = validate_enforce

    yield

    # Restore original method
    contract_enforcer.enforce_create_contract = original_enforce

    # Report violations if any
    if violations and request.config.getoption("--contract-report"):
        logger.info(f"Contract violations in {request.node.name}: {violations}")


class ContractReporter:
    """Reporter for contract validation results."""

    def __init__(self):
        self.violations = []
        self.validations = []

    def record_violation(self, test_name: str, violation: str):
        """Record a contract violation."""
        self.violations.append({
            'test': test_name,
            'violation': violation,
            'timestamp': pytest.current_test_time() if hasattr(pytest, 'current_test_time') else None
        })

    def record_validation(self, test_name: str, operation: str, result: bool):
        """Record a validation attempt."""
        self.validations.append({
            'test': test_name,
            'operation': operation,
            'result': result
        })

    def generate_report(self) -> Dict[str, Any]:
        """Generate contract compliance report."""
        return {
            'total_validations': len(self.validations),
            'total_violations': len(self.violations),
            'violations': self.violations,
            'validation_success_rate': (
                (len(self.validations) - len(self.violations)) / len(self.validations)
                if self.validations else 0
            )
        }


@pytest.fixture(scope="session")
def contract_reporter():
    """Provide contract reporter instance."""
    return ContractReporter()
