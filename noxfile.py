"""Nox sessions for BAS System test suites."""

from __future__ import annotations

from pathlib import Path

import nox


PYTHON_VERSIONS = ["3.11"]


def _ensure_coverage_directory() -> None:
    Path("coverage").mkdir(parents=True, exist_ok=True)


def _install_test_requirements(session: nox.Session) -> None:
    session.install("pytest>=7.4", "pytest-cov>=4.1", "coverage>=7.4")


def _ensure_coverage_directory() -> None:
    Path("coverage").mkdir(parents=True, exist_ok=True)


@nox.session(python=PYTHON_VERSIONS, reuse_venv=True, name="tests(unit_logging)")
def tests_unit_logging(session: nox.Session) -> None:
    """Run logging-library focused unit tests with coverage gating."""

    _install_test_requirements(session)

    _ensure_coverage_directory()
    session.env["COVERAGE_FILE"] = "coverage/.coverage.logging"

    default_args = [
        "tests/unit/logging",
        "--maxfail=1",
        "--cov=logging_lib",
        "--cov-context=test",
        "--cov-config=coverage/.coveragerc",
        "--cov-report=term-missing",
        "--cov-report=xml:coverage/logging.xml",
        "--cov-report=json:coverage/logging.json",
        "--cov-fail-under=85",
    ]

    session.run("pytest", *(session.posargs or default_args), env=session.env)


@nox.session(python=PYTHON_VERSIONS, reuse_venv=True, name="tests(unit_api)")
def tests_unit_api(session: nox.Session) -> None:
    """Run API-focused unit suites with coverage gating."""

    _install_test_requirements(session)

    _ensure_coverage_directory()
    session.env["COVERAGE_FILE"] = "coverage/.coverage.api"

    default_args = [
        "tests/unit/api",
        "tests/unit/api/http",
        "--maxfail=1",
        "--cov=apps/api",
        "--cov-context=test",
        "--cov-config=coverage/.coveragerc",
        "--cov-report=term-missing",
        "--cov-report=xml:coverage/api.xml",
        "--cov-report=json:coverage/api.json",
        "--cov-fail-under=90",
    ]

    session.run("pytest", *(session.posargs or default_args), env=session.env)


