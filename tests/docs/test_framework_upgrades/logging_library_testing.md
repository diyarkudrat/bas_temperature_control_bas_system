## Logging Library Testing Playbook (Phase 2 Stub)

- **Purpose:** placeholder for detailed guidance on fixtures, dispatcher harness usage, and coverage expectations. To be expanded in Phase 5.
- **Current Coverage Hooks:** use `nox -s tests(unit_logging)` for fast feedback; artifacts land under `coverage/logging.*`.
- **Key Fixtures:** `logger_manager`, `memory_logger`, `memory_sink` ensure deterministic state; heavy plugins remain disabled unless tests use `@pytest.mark.logging_use_plugins`.
- **Next Steps:** document dispatcher retry assertions, sink failure simulation patterns, and observability metric expectations.

