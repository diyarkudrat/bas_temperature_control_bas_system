"""Nox sessions orchestrating BAS System unit suites."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import nox


PYTHON_VERSIONS = ["3.11"]
PROJECT_ROOT = Path(__file__).parent

nox.options.sessions = [
    "tests_unit_api",
    "tests_unit_auth",
    "tests_unit_logging",
]


def _install_test_requirements(session: nox.Session) -> None:
    """Install core testing toolchain inside the session environment."""

    session.install("pytest>=7.4", "coverage>=7.4")


def _normalize_pythonpath(existing: str | None) -> str:
    parts = [str(PROJECT_ROOT)]
    if existing:
        parts.append(existing)
    return ":".join(part for part in parts if part)


def _build_env(session: nox.Session, targets: Iterable[str]) -> dict[str, str]:
    env = dict(session.env)
    env["PYTHONPATH"] = _normalize_pythonpath(env.get("PYTHONPATH"))
    env["COVERAGE_CMD"] = str(Path(session.bin) / "coverage")
    env["PYTEST_TARGETS"] = " ".join(targets)
    return env


def _run_suite(session: nox.Session, suite: str, targets: Iterable[str]) -> None:
    _install_test_requirements(session)

    script = PROJECT_ROOT / "scripts" / "coverage_baseline.sh"
    if not script.exists():
        session.error(f"Coverage orchestration script missing at {script}")

    env = _build_env(session, targets)

    args = ["bash", str(script), "--suite", suite]
    if session.posargs:
        args.append("--")
        args.extend(session.posargs)

    session.log("Running coverage baseline script: %s", " ".join(args[1:]))
    session.run(*args, env=env, external=True)


@nox.session(python=PYTHON_VERSIONS, reuse_venv=True, name="tests(unit_api)")
def tests_unit_api(session: nox.Session) -> None:
    """Execute API unit + HTTP suites with roadmap-themed coverage contexts."""

    targets = ["tests/unit/api", "tests/unit/api/http"]
    _run_suite(session, "api", targets)


@nox.session(python=PYTHON_VERSIONS, reuse_venv=True, name="tests(unit_auth)")
def tests_unit_auth(session: nox.Session) -> None:
    """Execute Auth service unit suites with roadmap-themed coverage contexts."""

    targets = ["tests/unit/auth"]
    _run_suite(session, "auth", targets)


@nox.session(python=PYTHON_VERSIONS, reuse_venv=True, name="tests(unit_logging)")
def tests_unit_logging(session: nox.Session) -> None:
    """Execute logging library unit suites with roadmap-themed coverage contexts."""

    targets = ["tests/unit/logging"]
    _run_suite(session, "logging", targets)


