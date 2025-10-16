# Monitoring & Cost

## Metrics & SLOs

- Reads/day: alert if > 1M
- Writes/day: alert if > 500k
- Storage: alert if > 1 GB
- Error rate: alert if > 2% over 5 minutes
- Performance: P50 ≤ 300ms, P95 ≤ 800ms for telemetry last-100 query
- Availability: ≥ 99.5%

## Budgets & Guardrails

- Dashboard budget: ≤ 50 reads/min per active dashboard
- Device writes: ≤ 5 writes/min per device

## Logging Policy

- Structured logs include `tenant_id`, `device_id`, `action`, read/write counts, latency
- No PII beyond audit IP/UA; mask usernames in non-audit logs
- Debug sampling ≤ 10% in prod

## Alerts Setup

- Cloud Monitoring policies for thresholds above
- Track index readiness and DAL error rates

## Dashboards

- Reads/writes/storage charts
- Error rates and latency histograms
- Tenancy distribution of reads
