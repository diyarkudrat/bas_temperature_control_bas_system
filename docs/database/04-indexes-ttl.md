# Indexes & TTL

## Composite Index (Telemetry)

Source of truth: `infra/firestore.indexes.json`

```json
{
  "indexes": [
    {
      "collectionGroup": "telemetry",
      "queryScope": "COLLECTION",
      "fields": [
        { "fieldPath": "tenant_id", "order": "ASCENDING" },
        { "fieldPath": "device_id", "order": "ASCENDING" },
        { "fieldPath": "timestamp_ms", "order": "DESCENDING" }
      ]
    }
  ]
}
```

Deploy:
```bash
gcloud firestore indexes composite create --quiet --project=PROJECT_ID --index-file=infra/firestore.indexes.json
```

Readiness gate:
```bash
gcloud firestore indexes composite list --project=PROJECT_ID \
  --filter="collectionGroup=telemetry AND state=READY"
```

## TTL Policies

Enable TTL on fields:
```bash
gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/telemetry/fields/timestamp_ms \
  --ttl=ON

gcloud alpha firestore fields ttls update \
  projects/PROJECT_ID/databases/(default)/collectionGroups/audit_log/fields/timestamp_ms \
  --ttl=ON
```

Recommended retention:
- telemetry: 90 days
- audit_log: 180 days

## Guidance

- Deploy indexes before enabling `USE_FIRESTORE_TELEMETRY`.
- If index is not ready, keep reads on SQLite; retry with backoff.
- Use TTL to control storage cost automatically.
