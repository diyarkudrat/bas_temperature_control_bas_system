# Access Patterns & Pagination

## Query Shapes

### Recent N telemetry for a device
```javascript
// Firestore SDK pseudo-code
const q = db.collection('telemetry')
  .where('tenant_id', '==', tenantId)
  .where('device_id', '==', deviceId)
  .orderBy('timestamp_ms', 'desc')
  .limit(N);
```

### Time-window query
```javascript
const since = Date.now() - windowMs;
const q = db.collection('telemetry')
  .where('tenant_id', '==', tenantId)
  .where('device_id', '==', deviceId)
  .where('timestamp_ms', '>=', since)
  .orderBy('timestamp_ms', 'desc')
  .limit(Nmax);
```

### User lookup
```javascript
const q = db.collection('users')
  .where('username', '==', username)
  .limit(1);
```

## Pagination

- Prefer document ID-based pagination using `startAfter(lastDoc)`
- For repository helpers, use `QueryOptions.offset` with last document ID
- Return `has_more` and `next_offset` to the caller

## Cost Tips

- Keep queries bounded by tenant/device/time and limit N
- Avoid unbounded scans; leverage the composite index
- Cache last results in memory if polling frequently (dashboard)

## Error Handling

- Treat Firestore `PERMISSION_DENIED` as 403 and audit it
- For index-not-ready errors, backoff and retry while keeping reads on SQLite until ready
