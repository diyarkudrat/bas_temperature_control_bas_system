## System Improvements Roadmap

### Architecture & Scalability
- **Adopt Stateless Deployment Model:** Remove module-level singletons in `apps/api/main.py` and refactor runtime wiring into explicit application factories so multiple gunicorn workers remain isolated.
- **Externalize Shared State:** Replace `InMemoryIdempotencyStore`, in-process rate limiter caches, and tenant context caches with Redis/Firestore-backed implementations; ensure configuration toggles default to durable stores.
- **Service Boundaries:** Break apart monolithic blueprints (`apps/api/http/org_routes.py`) into domain-focused services or micro-apps with clear contracts; introduce async workers (e.g., Celery/Cloud Tasks) for long-running org/device flows.
- **Deployment Artifacts:** Provide production-ready Dockerfiles, Helm charts, and infrastructure docs describing horizontal scaling, autoscaling triggers, and blue/green rollout playbooks.

### Reliability & Fault Tolerance
- **Holistic Health Checks:** Add readiness/liveness endpoints for API and auth services that validate downstream dependencies (Auth0, Firestore, Redis) with circuit-breaker aware status codes.
- **Unified Observability Stack:** Integrate metrics exporters (Prometheus/OpenTelemetry) and tracing (OTel instrumentation) across HTTP handlers, middleware, and adapters; publish dashboards for auth latency, limiter hit rates, and breaker states.
- **Resilient Persistence:** Implement durable retry queues for org provisioning and secret rotation, backed by Cloud Tasks/PubSub or Redis streams with dead-letter handling.
- **Chaos & Load Testing:** Automate fault-injection and high-concurrency tests (Locust/k6 + pytest reliability suite) tied to CI to prove behavior under surge and dependency failures.

### Code Quality & Readability
- **Modular Middleware:** Decompose `require_auth` and tenant middleware into composable classes/functions with unit coverage for each concern (rate limiting, revocation, tenant enforcement, auditing).
- **Domain-Centric Packages:** Move shared business logic out of Flask blueprints into application services; enforce boundary contracts via type hints and pydantic/dataclass schemas.
- **Testing Overhaul:** Replace legacy mocks referencing removed modules with targeted unit tests and integration suites covering the new architecture; enforce coverage thresholds and mutation testing for critical paths.
- **Tooling Hygiene:** Simplify `pytest.ini`, add `ruff`/`black`/`mypy` pipelines, and document contributor workflows to maintain consistent style and static analysis.

### Security & Best Practices
- **End-to-End Auth Hardening:** Deliver automated security tests for auth flows, including JWT validation, tenant isolation, and service-token replay protection; integrate with CI and security scanners (Bandit, Semgrep).
- **Secret Management Maturity:** Implement managed Secret Manager usage with envelope encryption, rotation schedules, and audit logging; remove long-lived in-memory fallback storage in production builds.
- **Service-to-Service Policy:** Enforce mTLS or signed JWT policies between services with centralized key rotation; document incident response procedures for token compromise.
- **Data Protection:** Classify and encrypt sensitive data at rest/in transit, add GDPR/SOC2-ready logging redaction, and provide DLP pipelines for exported telemetry.

### Resume & Portfolio Impact
- **Production Storytelling:** Publish an architecture decision record (ADR) set and ops runbook that narrate the reliability/security posture; include diagrams of request flow, scaling, and failover.
- **Automated Delivery:** Showcase CI/CD pipelines (GitHub Actions) running tests, security scans, and container publishing with promotion gates and release tagging.
- **Demonstrable Stability:** Provide benchmark results, chaos testing outcomes, and uptime SLIs to demonstrate measurable reliability improvements.
- **Live Reference Deployment:** Host a reference environment (e.g., Fly.io, GKE) with sanitized data and documented demo steps to let reviewers experience the hardened system end-to-end.

