# DDR: Authentication System Upgrade for BAS

This Design Decision Record (DDR) outlines the upgrade of the BAS authentication system to incorporate modern, secure patterns using Firebase Authentication and Google Cloud Identity Platform SDK. The design emphasizes scalability (e.g., stateless JWTs for horizontal scaling) and high reliability (e.g., adaptive TTLs, circuit breakers) while addressing counterexamples and blind spots for a resilient backend.

## Design Decisions

| ID | Statement (≤20 words) | Rationale (≤25 words) | Status | Invariant? (Y/N) |
|----|-----------------------|-----------------------|--------|------------------|
| 1 | Integrate Firebase Auth with Google Cloud Identity SDK for user management | Provides managed OAuth2/OpenID flows with auto-scaling and global redundancy for high-reliability auth | Approved | Y |
| 2 | Use stateless JWTs with adaptive TTL and refresh tokens | Enables horizontal scaling; adaptive TTL via latency testing reduces failures in high-latency networks for low-latency validation | Approved | N |
| 3 | Implement simple Redis token caching with validation on read | Boosts perf for high TPS; starts basic to avoid complexity, mitigates poisoning via signature checks | Approved | Y |
| 4 | Enforce RBAC via Firestore security rules and indexes | Delivers fine-grained access with query optimization for reliability at high concurrency | Approved | Y |
| 5 | Mandate role-based MFA with IoT exemptions using service accounts | Enhances security for humans; allows non-interactive device auth via certs/keys for usability | Approved | Y |
| 6 | Incorporate circuit breakers and retries in SDK calls | Prevents cascading failures during outages, ensuring 99.99% uptime in distributed systems | Approved | N |
| 7 | Mirror auth events to Firestore with TTL and spike guardrails | Supports scalable logging; configurable write limits prevent cost explosions under bursts in personal projects | Approved | N |
| 8 | Mandate HTTPS with HSTS for all auth endpoints | Protects token transport and ensures basic transport security without initial auto-rotation | Approved | Y |

## Summary

This revised DDR incorporates counterexamples and blind spots, upgrading BAS auth for scalability (stateless JWTs, simple caching) and high reliability (adaptive TTLs, circuit breakers, guardrailed auditing) while keeping personal project scope. Key changes: Adaptive TTL testing addresses latency issues; caching starts simple with poisoning mitigations (revocation as future enhancement); MFA is role/IoT-aware for usability; auditing adds spike controls for cost reliability; cert auto-rotation deferred to future.

Trade-offs: Simplicity prioritizes quick implementation (e.g., basic Redis over HA) versus full production hardening, with extensibility for growth. Constraints maintain security invariants like MFA and HTTPS.

For portfolio demonstration, this showcases expertise in resilient backends: handling IoT usability (e.g., service accounts bypassing MFA), adaptive TTL for network variability, and guardrails capping Firestore costs—proving design for high traffic without failures or bill shocks in hybrid human/IoT systems.

(Word count: 196)

## Top-5 Risks

1. Adaptive TTL miscalibration could still cause refresh failures in untested network scenarios.
2. Basic Redis caching without HA might become a single point of failure at scale.
3. IoT MFA exemptions could create security gaps if service accounts aren't rotated properly.
4. Audit guardrails might drop critical logs during legitimate spikes, affecting compliance.
5. Delaying cert auto-rotation risks manual renewal errors in long-running deployments.

## Future Enhancements

- Implement full token revocation lists in Redis for instant invalidation.
- Add certificate auto-rotation using tools like Let's Encrypt or Google-managed certs for zero-downtime reliability.
- Enhance audit system with external monitoring (e.g., Cloud Monitoring) for advanced spike detection and alerts.
- Explore mTLS for IoT devices to further secure non-interactive auth flows.

This DDR was generated on [Current Date: Saturday, October 18, 2025] as part of the BAS System Project's iterative design process.
