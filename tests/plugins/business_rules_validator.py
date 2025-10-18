"""Pytest plugin for validating business rules during test execution."""

import pytest
import logging
from typing import Dict, Any, List, Optional

from ..utils.business_rules import BusinessRules

logger = logging.getLogger(__name__)


class BusinessRulesValidator:
    """Validator for business rules compliance."""

    def __init__(self):
        self.violations = []
        self.validations = []
        self.business_rules = BusinessRules()

    def validate_auth_check(self, **kwargs) -> Dict[str, Any]:
        """Validate authentication rules."""
        result = self.business_rules.auth_check(**kwargs)
        self._record_validation('auth_check', result)
        return result

    def validate_password_policy(self, password: str) -> Dict[str, Any]:
        """Validate password policy rules."""
        result = self.business_rules.password_policy_check(password)
        self._record_validation('password_policy', result)
        return result

    def validate_tenant_isolation(self, requested_tenant: str, allowed_tenant: str) -> Dict[str, Any]:
        """Validate tenant isolation rules."""
        result = self.business_rules.tenant_isolation_check(requested_tenant, allowed_tenant)
        self._record_validation('tenant_isolation', result)
        return result

    def validate_rate_limit(self, attempts: List[int], window_ms: int, max_attempts: int) -> Dict[str, Any]:
        """Validate rate limiting rules."""
        result = self.business_rules.rate_limit_check(attempts, window_ms, max_attempts)
        self._record_validation('rate_limit', result)
        return result

    def validate_ttl_enforce(self, created_at_ms: int, ttl_days: Optional[int] = None) -> Dict[str, Any]:
        """Validate TTL enforcement rules."""
        result = self.business_rules.ttl_enforce(created_at_ms, ttl_days)
        self._record_validation('ttl_enforce', result)
        return result

    def _record_validation(self, rule_name: str, result: Dict[str, Any]):
        """Record validation attempt and any violations."""
        self.validations.append({
            'rule': rule_name,
            'valid': result.get('valid', True),
            'violations': result.get('violations', [])
        })

        if not result.get('valid', True):
            violations = result.get('violations', [])
            for violation in violations:
                self.violations.append({
                    'rule': rule_name,
                    'violation': violation
                })
                logger.warning(f"Business rule violation in {rule_name}: {violation}")

    def get_violation_summary(self) -> Dict[str, Any]:
        """Get summary of business rule violations."""
        return {
            'total_validations': len(self.validations),
            'total_violations': len(self.violations),
            'violations_by_rule': self._group_violations_by_rule(),
            'compliance_rate': (
                (len(self.validations) - len(self.violations)) / len(self.validations) * 100
                if self.validations else 100
            )
        }

    def _group_violations_by_rule(self) -> Dict[str, int]:
        """Group violations by rule name."""
        grouped = {}
        for violation in self.violations:
            rule = violation['rule']
            grouped[rule] = grouped.get(rule, 0) + 1
        return grouped


@pytest.fixture(scope="session")
def business_rules_validator():
    """Provide business rules validator instance."""
    return BusinessRulesValidator()


@pytest.fixture(autouse=True)
def business_rules_validation(request, business_rules_validator):
    """Automatically validate business rules during test execution."""
    # Only validate for tests marked with business_rules marker
    if not request.node.get_closest_marker("business_rules"):
        yield
        return

    # Store original validator state
    initial_violations = len(business_rules_validator.violations)

    yield

    # Check for new violations
    new_violations = len(business_rules_validator.violations) - initial_violations
    if new_violations > 0:
        logger.info(f"Business rules validation completed for {request.node.name}: {new_violations} violations found")


def pytest_configure(config):
    """Configure pytest with business rules validation."""
    config.addinivalue_line(
        "markers", "business_rules: Tests that validate business rules"
    )


def pytest_addoption(parser):
    """Add command line options for business rules validation."""
    # Register custom ini options used in pytest.ini to avoid warnings
    parser.addini(
        "business_rule_violation_fail_threshold",
        "Maximum number of business rule violations allowed (string; convert to int where used)",
        default="0",
        type="string",
    )
    group = parser.getgroup("contract")
    group.addoption(
        "--business-rule-violation-threshold",
        type=int,
        default=0,
        help="Maximum number of business rule violations allowed (default: 0)"
    )


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Report business rules validation summary."""
    # Find business rules validator in session
    validator = None
    for item in getattr(session, 'items', []) or []:
        funcargs = getattr(item, 'funcargs', None)
        if isinstance(funcargs, dict) and 'business_rules_validator' in funcargs:
            validator = funcargs['business_rules_validator']
            break

    if validator and validator.validations:
        summary = validator.get_violation_summary()
        print(f"\n=== Business Rules Validation Summary ===")
        print(f"Total Validations: {summary['total_validations']}")
        print(f"Total Violations: {summary['total_violations']}")
        print(".2f")

        if summary['violations_by_rule']:
            print("Violations by Rule:")
            for rule, count in summary['violations_by_rule'].items():
                print(f"  {rule}: {count}")

        # Fail if violations exceed threshold
        threshold = session.config.getoption("--business-rule-violation-threshold", 0)
        if summary['total_violations'] > threshold:
            pytest.exit(f"Business rule violations ({summary['total_violations']}) exceeded threshold ({threshold})")
