# BAS System Testing Framework

This repository is migrating to a layered test layout (Phase 8). Existing tests remain in-place; we add the new structure now to minimize future churn.

## Structure (target)

```
tests/
  unit/
    application/
    domains/
    platform/
  integration/
    adapters/
  contracts/
    providers/
    db/
  fixtures/
  plugins/
  utils/
```

Notes:
- Unit tests align with layers: `application`, `domains`, `platform`.
- Integration tests focus on IO adapters and emulators.
- Contract tests capture behavioral expectations for providers and datastores.
- We keep legacy folders (e.g., `unit/auth`, `unit/http`, `unit/firestore`) until Phase 10 import rewrites complete.

## Documentation Index

- [01 — Overview](./docs/01-overview.md)
- [02 — Testing Framework](./docs/02-testing-framework.md)
- [03 — Fixtures](./docs/03-fixtures.md)
- [04 — Markers](./docs/04-markers.md)
- [05 — Plugins](./docs/05-plugins.md)
- [06 — Business Rules](./docs/06-business-rules.md)
- [07 — Contracts](./docs/07-contracts.md)
- [08 — Validators](./docs/08-validators.md)
- [09 — Mocks](./docs/09-mocks.md)
- [10 — Troubleshooting](./docs/10-troubleshooting.md)
- [11 — Style & Conventions](./docs/11-style-and-conventions.md)
- [12 — Test Commands](./docs/12-test-commands.md)
