# BAS Service Account → Firestore Integration

## Overview
This document explains how the BAS server authenticates to Google Cloud Firestore using a dedicated service account via Application Default Credentials (ADC), how it interacts with Firestore collections through repository “stores,” and the security benefits of this setup.

## Components
- Project: `bas-system-project`
- Service account: `bas-server-firestore@bas-system-project.iam.gserviceaccount.com`
- Auth method: ADC using `GOOGLE_APPLICATION_CREDENTIALS` → JSON key path
- Minimal custom role: `bas_firestore_minimal_access`
  - Permissions: `datastore.entities.create/delete/get/list/update`, `datastore.indexes.list`
- Firestore database: `(default)` (Native mode)
- Collections used: `telemetry`, `users`, `sessions`, `audit_log`, `devices`

## How Authentication Works
1. BAS server process has `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json` set.
2. Code calls `google.auth.default()` to obtain credentials and project ID automatically.
3. A Firestore client is constructed with these credentials; all requests are authorized as the service account.
4. IAM enforces the custom role to allow only necessary CRUD and query operations.

Relevant code paths:
- `server/auth/firestore_client.py` (Firestore client via ADC)
- `server/services/firestore/service_factory.py` (lazy client creation + health check)

## Stores → Collections Mapping
Application stores encapsulate collection access and business rules. Collections are created on first write.
- `TelemetryRepository` → `telemetry`
- `UsersRepository` → `users`
- `SessionsStore` → `sessions`
- `AuditLogStore` → `audit_log`
- `DevicesStore` → `devices`

## Security Benefits
- Least privilege: Custom role grants only document CRUD and index listing—no admin/destructive APIs.
- Credential isolation: Dedicated non-human identity for the server; no user creds in code.
- Secret hygiene: Key path is provided via environment; key files are ignored by Git.
- Auditable: Actions are attributable to the service account; app can log to `audit_log`.
- Revocable/rotatable: Keys/permissions can be changed without code edits.

## Operational Notes
- Key management: store securely outside the repo; rotate periodically; revoke old keys promptly.
- Monitoring: alert on permission denials and unusual access; review IAM bindings regularly.
- Indexes: keep `infra/firestore.indexes.yaml` aligned with query patterns; provision before features that need them.

## Future Enhancements (Simple)
- Use Google Secret Manager for key storage/rotation; remove local JSON key.
- Adopt workload identity (no keys) when running on GCP-managed runtimes.
- Split roles (read-only telemetry, admin ops) for finer access control.
- Expand audit coverage for privileged operations.
- Automate index provisioning in CI/CD with drift detection.

---
For implementation details, see `server/auth/firestore_client.py` and `server/services/firestore/service_factory.py`.
