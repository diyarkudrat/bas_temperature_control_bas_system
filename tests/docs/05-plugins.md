# Plugins

## Overview

Custom pytest plugins extend the framework with contract enforcement and developer ergonomics (i.e., smoother developer experience: fewer imports, consistent CLI flags, reduced boilerplate, clearer error messages).

## CLI Flags

- `--contract-validation` — enable runtime contract checks
- `--contract-report` — emit contract compliance report

These are typically wired in `tests/plugins/` (e.g., `contract_enforcer.py`) and activated via `conftest.py`.

## Runtime Contract Enforcement

When enabled, core service/store methods are wrapped to:

- Pre-validate inputs against protocols and business rules
- Execute the operation
- Post-validate outputs and side effects

Violations raise clear exceptions to fail fast and surface root causes.

## Import Helpers

Import helpers (e.g., `tests/plugins/import_manager.py`) provide stable import paths and dependency setup for tests, minimizing boilerplate. Examples of ergonomics:

- Single helper import instead of multiple path manipulations
- Uniform activation of flags across suites via `conftest.py`
- Standard error formatting for faster diagnosis


