# Migration & Rollout

## Phased Plan

1) Telemetry → 2) Audit → 3) Auth (force re-login)

- Enable feature flags in sequence
- Verify functionality and performance at each phase
- Use emulator in dev; confirm indexes/TTLs in stg before prod

## Readiness Gates

- Composite index READY for telemetry reads flip
- Basic health check on client and repos
- Error rate < 2% over 5 minutes

## Flags

- `USE_FIRESTORE_TELEMETRY`
- `USE_FIRESTORE_AUDIT`
- `USE_FIRESTORE_AUTH`

## Rollback

- Disable specific flag(s) to return to SQLite path
- Telemetry/audit writes during Firestore window are authoritative (append-only)
- Auth rollback requires re-login

## Dual-write (optional)

- Briefly dual-write telemetry (SQLite + Firestore); keep reads on SQLite until index READY and sample compare is green

## Users & Sessions

- Users: export from SQLite; ensure UUIDv4 `user_id`; import; verify logins
- Sessions: do not migrate; require re-login at auth cutover

## Backfill

- Telemetry: optional last 7 days in batched writes (≤ 5 writes/min/device)
- Audit: optional 7–30 days with `source='sqlite_backfill'`

## Observability

- Track read/write counts, storage, latency, error rate
- Alert policies set before prod cutover
