# Testing Framework Guide (Deep Dive)

This guide explains how the framework fits together for future maintainers.

## Directory Map

- `pytest.ini` — markers, thresholds, reporting
- `tests/conftest.py` — global hooks, fixture registration
- `tests/fixtures/` — shared test fixtures
- `tests/utils/` — `assertions.py`, `business_rules.py`
- `tests/plugins/` — CLI flags, contract enforcer, import helpers
- `tests/contracts/` — protocols, validators, optimized mocks
- `tests/unit/` — domain-organized tests

## Execution Lifecycle

1. Pytest loads config and plugins
2. Imports tests and fixtures
3. Optional: wraps services with contract enforcer
4. Runs tests with fixtures
5. Collects and reports results (optionally contract report)

## Extending the Framework

- Add a new domain: create fixtures, add marker, write tests
  ```python
  # tests/fixtures/device_fixtures.py
  import pytest
  @pytest.fixture
  def sample_device():
      return {"device_id": "dev-1", "name": "Thermostat"}
  ```
  ```python
  # tests/unit/device/test_device_manager.py
  import pytest
  @pytest.mark.device
  @pytest.mark.unit
  class TestDeviceManager:
      def test_add(self, sample_device):
          assert sample_device["device_id"]
  ```

- Add a rule: implement in `business_rules.py`, document in rules doc
  ```python
  # tests/utils/business_rules.py
  class BusinessRules:
      def device_id_format(self, device_id: str):
          ok = device_id.startswith("dev-")
          return {"valid": ok, "violations": [] if ok else ["bad format"]}
  ```

- Add a contract: update protocols, validators, and mocks
  ```python
  # tests/contracts/base.py (conceptual)
  from typing import Protocol
  class DeviceStoreProtocol(Protocol):
      def add(self, device: dict) -> bool: ...
  ```


## Style and Conventions

Moved to a dedicated page: see `10-style-and-conventions.md`.

## References

See docs in this folder for focused topics and examples.