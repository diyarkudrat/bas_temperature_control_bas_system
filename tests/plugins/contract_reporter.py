"""Pytest plugin for generating contract compliance reports."""

import pytest
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..contracts.firestore import ContractEnforcer
from ..utils.business_rules import BusinessRules


class ContractComplianceReporter:
    """Generate detailed reports on contract compliance."""

    def __init__(self):
        self.test_results = []
        self.contract_violations = []
        self.business_rule_violations = []
        self.performance_metrics = []

    def record_test_result(self, test_name: str, status: str, duration: float):
        """Record individual test result."""
        self.test_results.append({
            'test_name': test_name,
            'status': status,
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        })

    def record_contract_violation(self, test_name: str, violation: str, severity: str = 'error'):
        """Record contract violation."""
        self.contract_violations.append({
            'test_name': test_name,
            'violation': violation,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })

    def record_business_rule_violation(self, test_name: str, rule: str, violation: str):
        """Record business rule violation."""
        self.business_rule_violations.append({
            'test_name': test_name,
            'rule': rule,
            'violation': violation,
            'timestamp': datetime.now().isoformat()
        })

    def record_performance_metric(self, operation: str, duration: float, memory_usage: Optional[float] = None):
        """Record performance metrics for contract operations."""
        self.performance_metrics.append({
            'operation': operation,
            'duration_ms': duration,
            'memory_kb': memory_usage,
            'timestamp': datetime.now().isoformat()
        })

    def generate_report(self, output_path: str = None) -> Dict[str, Any]:
        """Generate comprehensive contract compliance report."""
        report = {
            'summary': {
                'total_tests': len(self.test_results),
                'passed_tests': len([t for t in self.test_results if t['status'] == 'passed']),
                'failed_tests': len([t for t in self.test_results if t['status'] == 'failed']),
                'contract_violations': len(self.contract_violations),
                'business_rule_violations': len(self.business_rule_violations),
                'generated_at': datetime.now().isoformat()
            },
            'contract_violations': self.contract_violations,
            'business_rule_violations': self.business_rule_violations,
            'performance_metrics': self.performance_metrics,
            'test_results': self.test_results
        }

        # Calculate compliance score
        total_operations = len(self.contract_violations) + len(self.business_rule_violations) + len(self.performance_metrics)
        violations = len(self.contract_violations) + len(self.business_rule_violations)
        report['summary']['compliance_score'] = (
            (total_operations - violations) / total_operations * 100
            if total_operations > 0 else 100
        )

        # Write to file if path provided
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            report['output_file'] = output_path

        return report

    def print_summary(self):
        """Print human-readable summary."""
        summary = self.generate_report()['summary']
        print("\n=== Contract Compliance Report ===")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed_tests']}")
        print(f"Failed: {summary['failed_tests']}")
        print(f"Contract Violations: {summary['contract_violations']}")
        print(f"Business Rule Violations: {summary['business_rule_violations']}")
        print(".2f")
        print(f"Generated: {summary['generated_at']}")


@pytest.fixture(scope="session")
def contract_reporter():
    """Provide contract compliance reporter."""
    return ContractComplianceReporter()


def pytest_configure(config):
    """Configure pytest with reporting options."""
    config.addinivalue_line(
        "addopts", "--contract-report-json"
    ) if config.getoption("--contract-report", default=False) else None


def pytest_addoption(parser):
    """Add command line options for contract reporting."""
    group = parser.getgroup("contract")
    group.addoption(
        "--contract-report-json",
        type=str,
        default="contract_report.json",
        help="Path to save contract compliance report JSON"
    )


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    """Generate contract report at end of test session."""
    if not session.config.getoption("--contract-report"):
        return

    # Get reporter from session
    reporter = None
    for item in getattr(session, 'items', []) or []:
        funcargs = getattr(item, 'funcargs', None)
        if isinstance(funcargs, dict) and 'contract_reporter' in funcargs:
            reporter = funcargs['contract_reporter']
            break

    if reporter:
        output_path = session.config.getoption("--contract-report-json")
        report = reporter.generate_report(output_path)
        reporter.print_summary()
    else:
        # No tests used the contract_reporter fixture; nothing to generate
        return
