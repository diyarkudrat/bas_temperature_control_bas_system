# Alerting Service - Design Decision Record (DDR)

| ID | Statement (<=20w) | Rationale (<=25w) | Status | Invariant? |
|----|-------------------|-------------------|--------|------------|
| D1 | Use Twilio for SMS alerts | Proven reliability, easy integration, global reach | Proposed | N |
| D2 | Support email alongside SMS | Broader reach, cost-effective for non-urgent alerts | Proposed | N |
| D3 | Categorize alerts by severity: critical, warning, info | Prioritizes response, filters noise | Proposed | Y |
| D4 | Config via validated JSON with semantic checks, versioning, and staging/async test workflows | Prevents inconsistencies; staging/tests avoid bad rollouts | Proposed | Y |
| D5 | Backend event hooks with async confirmations and retries | Low-latency delivery and at-least-once for critical | Proposed | N |
| D6 | Rate limiting with burst control, global throttling via atomic shared counters, monitoring + in-app fallback | Prevents spikes/cost overruns across distributed instances | Proposed | Y |
| D7 | Log attempts with automatic redaction, sampling, and async buffering | Auditable, privacy-safe, and scalable under floods | Proposed | Y |
| D8 | Secure channels with enforced minimization, default link-only for sensitive alerts, optional E2E | Reduces interception risk without assuming user crypto | Proposed | Y |

### Summary
A pragmatic alerting service for the BAS backend using Twilio (SMS) and email. Alerts are severity-driven (critical, warning, info) and governed by JSON configuration with semantic validation, versioning, and staging plus test workflows to avoid misconfigurations. Alerts are triggered via backend event hooks using async confirmations and retries to keep critical-path latency low while providing at-least-once delivery for critical events. Cost and reliability are protected through rate limiting with burst control and global throttling backed by atomic shared counters and redundant monitoring (cloud plus in-app fallbacks). Logging captures alert attempts with automatic redaction, sampling, and async buffering to maintain privacy and performance during floods. Transport security is enforced by content minimization and link-only messages for sensitive cases, with optional end-to-end encryption for recipients that opt in.

### Top-5 Risks
- Twilio downtime blocks SMS: mitigate with email fallback and retries.
- Config errors cause floods/misses: staging, semantic validation, and required tests.
- High SMS volume spikes costs: budgets, burst control, global throttling, redundant monitoring.
- Privacy leaks in alerts: mandatory redaction, minimization, link-only for sensitive payloads.
- Delivery failures during spikes: async confirmations, retries, and optional queuing.
