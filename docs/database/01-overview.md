# Database Overview (Firestore)

## 🎯 Quick Summary

- Primary store: **Google Cloud Firestore (Native mode)** for telemetry, users/sessions, audit, and devices.
- Goals: low ops, predictable cost (<$50/mo at showcase scale), built-in TTL cleanup, multi-tenant ready.
- Environments: local emulator for dev; GCP project per env (dev/stg/prod).

---

## ✅ Why Firestore

- Serverless and managed (no patching, backups, or scaling overhead)
- Pay-per-use with automatic indexing and TTL policies
- Fits patterns: time-series telemetry, short-lived sessions, append-only audit
- Strong IAM and GCP integration (Secret Manager, Monitoring)

---

## 📦 What We Store

- `telemetry`: time-series device data `(tenant_id, device_id, timestamp_ms)`
- `users`: operators/admins, credentials metadata, roles
- `sessions`: opaque sessions with expiry and fingerprint binding
- `audit_log`: append-only security events with TTL
- `devices`: device registry and metadata

---

## 🧭 How to Use These Docs

1. Read [02-architecture.md](02-architecture.md) for wiring and flows.
2. See [03-data-model.md](03-data-model.md) for schemas and examples.
3. Deploy [04-indexes-ttl.md](04-indexes-ttl.md) before enabling flags.
4. Follow [07-service-layer.md](07-service-layer.md) for coding patterns.
5. For rollout, see [09-migration-rollout.md](09-migration-rollout.md).

---

## 🚩 Feature Flags

- `USE_FIRESTORE_TELEMETRY`
- `USE_FIRESTORE_AUTH`
- `USE_FIRESTORE_AUDIT`
- `FIRESTORE_EMULATOR_HOST` (local dev)
- `GOOGLE_CLOUD_PROJECT` (env project)

Details in [09-migration-rollout.md](09-migration-rollout.md).

---

## 🔐 Multi-Tenancy at a Glance

- Include `tenant_id` in relevant collections.
- Middleware and DAL enforce tenant isolation; cross-tenant → 403 + audit.
- Clients must pass `TENANT_ID_HEADER` consistently.

---

## 💸 Cost Guardrails

- Budgets and alerts: [11-monitoring-cost.md](11-monitoring-cost.md)
- Query and pagination tips: [05-access-patterns.md](05-access-patterns.md)

---

## 🧪 Local Development

Use Firestore Emulator:

```bash
gcloud beta emulators firestore start --host-port=127.0.0.1:8080
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080
export GOOGLE_CLOUD_PROJECT=your-project-id
```

Testing guidance in [10-testing.md](10-testing.md).
