# Phase 2 Patch Plan

## Summary (85 words)
This patch plan implements core prototypes for Phase 2: Refactor SSE service to use async Redis pub/sub for distributed real-time messaging, and enhance Firestore services with dependency injection for modular, testable repositories. Focuses on async I/O, DI patterns, and low-latency budgets to demonstrate scalable backend design. Aligns with DDR invariants for modularity, reliability, and tenant isolation.

## Patch Plan

| file | op | functions/APIs | tests | perf/mem budget | risk |
|------|----|----------------|-------|-----------------|------|
| server/services/sse_service/redis_backend.py | modify | Refactor to async using aioredis; implement async publish and subscriber loop | Unit tests for async pub/sub; integration with Redis emulator | p99 &lt;50ms; mem &lt;5MB per connection | Async migration may introduce concurrency issues |
| server/services/sse_service/service.py | modify | Update publish/subscribe to async methods; async iterator for subscriptions | Async flow tests; subscriber count accuracy | p99 &lt;30ms publish; queue max 100 | Breaking sync API compatibility |
| server/services/sse_service/factory.py | modify | Add async init; inject async Redis client via DI | Factory tests with mocked async client | n/a | Emulator attachment failures |
| server/services/sse_service/hub.py | modify | Convert in-process hub to async queues and heartbeats | Heartbeat and fan-out tests in async mode | p99 &lt;20ms fan-out; mem &lt;1MB | Dropped messages during async refactor |
| server/services/firestore/service_factory.py | modify | Implement manual DI wiring in composition root; constructor injection for I/O boundaries (client) | DI resolution and injection tests | n/a | Breaking existing repository instantiation |
| server/services/firestore/base.py | modify | Add interfaces only for injectable I/O (e.g., IClient); no interfaces for helpers | Repository method tests with injected mocks | p99 &lt;20ms per op; mem &lt;2MB | Overhead from DI layers |
| server/services/firestore/telemetry_store.py | modify | Use constructor injection for client; singleton lifetime | Telemetry CRUD tests with DI | p99 &lt;40ms query; mem &lt;3MB | Data consistency in injected ops |
| server/services/firestore/users_store.py | modify | Refactor for constructor DI; validate injections in create/update | User management tests with mocks | p99 &lt;30ms; mem &lt;2MB | Security risks if injections bypassed |
| server/requirements.txt | modify | Add aioredis and injector dependencies | n/a | n/a | Dependency conflicts |
| server/bas_server.py | modify | Set up composition root for manual wiring of services and repositories | End-to-end async SSE tests | p99 &lt;50ms e2e; mem &lt;50MB total | App startup failures with async init |
| docs/api/refactor_design/phase_2_plan.md | create | Document patch plan (this file) | n/a | n/a | Documentation drift |

## Notes
- Use Python's asyncio for SSE async operations; ensure compatibility with existing sync routes via adapters.
- For DI, use manual constructor injection with a composition root in bas_server.py; define interfaces only for I/O boundaries with ≥2 impls or test needs; default to singleton lifetimes; no setters or global singletons.
- Total changes target &lt;500 LoC for prototype focus.
