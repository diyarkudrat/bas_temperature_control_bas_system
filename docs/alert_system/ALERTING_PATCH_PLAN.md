# Alerting Service - Patch Plan

## Summary
Implement the alerting service by adding a new AlertService in services, integrating Twilio and email, adding configurations, event hooks in bas_server, rate limiting, secure logging, and associated tests. Focus on async operations, validation, and security invariants from DDR. Total changes span new files and modifications to existing backend components.

## Patch Plan

| file | op | functions/APIs | tests | perf/mem budget | risk |
|------|----|----------------|-------|-----------------|------|
| server/services/alerting.py | add | AlertService class, init_twilio, send_sms | unit: mock Twilio send, error handling | &lt;100ms per send, 1MB | Twilio API downtime |
| server/services/alerting.py | modify | send_email, fallback logic | unit: mock email, fallback tests | &lt;100ms, 1MB | Spam filtering/blocking |
| server/models/alert.py | add | AlertSeverity enum, Alert dataclass | unit: enum validation, serialization | negligible | Severity misclassification |
| server/config/alert_config.json | add | JSON schema for alerts | integration: load/validate | - | Configuration parse errors |
| server/services/config_validator.py | add | validate_alert_config with semantic checks | unit: valid/invalid configs, versioning | &lt;50ms | Bad config rollout |
| server/bas_server.py | modify | add_event_hook, trigger_alert on events | integration: event triggering, async confirmation | &lt;10ms added latency | Missed critical events |
| server/services/alerting.py | modify | async_send with retries/confirmations | unit: async mocks, retry logic | queue 5MB | Delivery failures under load |
| server/services/rate_limiter.py | add | AlertRateLimiter with burst/global throttling | stress: limit enforcement, shared counters | &lt;5ms per check, shared mem 500KB | Cost overruns from spikes |
| server/services/logger.py | modify | log_alert_attempt with redaction/sampling/async buffer | unit: redaction, perf: flood simulation | buffer 5MB | Privacy leaks or log floods |
| server/services/alerting.py | modify | minimize_content, secure_link_generator, optional E2E (future enhancement) | unit: content minimization, link tests | negligible | Interception/data exposure |
| tests/unit/test_alerting.py | add | Comprehensive unit tests for AlertService | pytest: coverage &gt;80%, edge cases | - | Undetected bugs |
| tests/integration/test_alerting.py | add | End-to-end alerting flow tests | integration: mock providers, event to delivery | - | Integration failures |

## Notes
- Ensure all changes respect multi-tenancy from existing auth system.
- Use Firestore for alert storage if enabled, extending AlertsRepository.
- Budgets are per-operation estimates; monitor in production.
