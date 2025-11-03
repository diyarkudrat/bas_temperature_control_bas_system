# Organization Creation Implementation Plan

## 1. Current State Assessment

- **HTTP routing surface** — Not implemented. The API only wires legacy control, telemetry, and auth blueprints; there is no organization/signup/invite/device blueprint today.

```22:35:apps/api/http/router.py
    app.register_blueprint(control_bp)
    logger.debug("Registered control blueprint")

    app.register_blueprint(telemetry_bp)
    logger.debug("Registered telemetry blueprint")

    app.register_blueprint(auth_bp)
    logger.debug("Registered auth blueprint")
```

- **Standalone auth service** — Implemented. Login/logout/session flows and rate limiting exist, providing a foundation for provisioning but lacking organization-specific APIs.

```105:198:apps/auth_service/http/auth_routes.py
@auth_bp.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = getattr(request, "auth_config", None)
    if not cfg or not getattr(cfg, "auth_enabled", False):
        logger.warning(
            "Login attempt rejected: auth disabled",
            extra={"config_present": cfg is not None},
        )
        return jsonify({"error": "Authentication disabled"}), 503

    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        logger.warning(
            "Login attempt missing required fields",
            extra={"username_present": bool(username)},
        )
        return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400

    username_hash = _scrub_identifier(username)
    remote_hash = _scrub_identifier(request.remote_addr)
    logger.info(
        "Login attempt received",
        extra={"username_hash": username_hash, "remote_hash": remote_hash},
    )

    limiter, audit, sessions, users, _ = _get_request_components()
    if sessions is None or users is None:
        logger.error(
            "Auth runtime not fully initialized",
            extra={"sessions_missing": sessions is None, "users_missing": users is None},
        )
        return jsonify({"error": "Authentication system unavailable"}), 500

    try:
        allowed, message = limiter.is_allowed(request.remote_addr, username) if limiter else (True, "Allowed")
        if not allowed:
            logger.info(
                "Login rate limited",
                extra={"username_hash": username_hash, "remote_hash": remote_hash, "message": message},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429

        user = users.authenticate_user(username, password)
        if not user:
            if limiter:
                limiter.record_attempt(request.remote_addr, username)
            logger.info(
                "Login failed: invalid credentials",
                extra={"username_hash": username_hash, "remote_hash": remote_hash},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "INVALID_CREDENTIALS")
            return jsonify({"error": "Invalid credentials", "code": "AUTH_FAILED"}), 401

        if user.is_locked():
            logger.info(
                "Login failed: account locked",
                extra={"username_hash": username_hash},
            )
            if audit:
                audit.log_auth_failure(username, request.remote_addr, "ACCOUNT_LOCKED")
            return jsonify({"error": "Account locked", "code": "USER_LOCKED"}), 423

        session = sessions.create_session(username, user.role, request)
        users.update_last_login(username)
        if limiter:
            limiter.clear_attempts(request.remote_addr, username)
        if audit:
            audit.log_auth_success(username, request.remote_addr, session.session_id)

        logger.info(
            "Login succeeded",
            extra={
                "username_hash": username_hash,
                "role": user.role,
                "tenant_present": bool(getattr(session, "tenant_id", None)),
            },
        )

        resp = jsonify({
            "status": "success",
            "expires_in": cfg.session_timeout,
            "user": {
                "username": username,
                "role": user.role,
                "user_id": getattr(session, "user_id", "unknown"),
                "tenant_id": getattr(session, "tenant_id", None),
            },
        })
        resp.set_cookie(
            "bas_session_id",
            session.session_id,
            max_age=cfg.session_timeout,
            httponly=True,
            secure=True,
            samesite="Strict",
        )
        return resp
    except Exception as exc:  # noqa: BLE001
        logger.exception("Auth login failed")
        return jsonify({"error": "Internal server error"}), 500
```

- **Tenant isolation middleware** — Partial. `TenantMiddleware` resolves tenant context and audits conflicts, but no current routes invoke `require_tenant`/`enforce_tenant_isolation`, nor are tenant-scoped repositories wired yet.

```192:300:apps/api/http/middleware/tenant.py
class TenantMiddleware:
    """Middleware for enforcing multi-tenant isolation."""

    def __init__(
        self,
        auth_config: AuthConfig,
        audit_sink: Optional[TenantAuditSink] = None,
    ) -> None:
        self.auth_config = auth_config
        self.tenant_header = auth_config.tenant_id_header
        self._resolver = TenantResolver(
            self.tenant_header,
            cache_ttl_s=120,
            cache_capacity=1024,
        )
        if audit_sink is None:
            self._audit_sink: Optional[TenantAuditSink] = None
        else:
            missing = [
                name
                for name in ("log_permission_denied", "log_tenant_violation")
                if not hasattr(audit_sink, name)
            ]
            if missing:
                logger.warning(
                    "Provided audit sink is missing required methods",
                    extra={"missing": missing},
                )
                self._audit_sink = None
            else:
                self._audit_sink = audit_sink  # type: ignore[assignment]

    def _attach_context(self, request_obj: Request, context: TenantContext) -> None:
        try:
            setattr(request_obj, "_tenant_context", context)
        except Exception:
            pass
        try:
            setattr(request_obj, "tenant_id", context.tenant_id)
        except Exception:
            pass
        if has_request_context() and context.tenant_id is not None:
            try:
                g.tenant_id = context.tenant_id
            except Exception:
                pass

    def _handle_conflict(self, request_obj: Request, context: TenantContext) -> None:
        if not context.conflict:
            return

        logger.warning(
            "Tenant header mismatch; using session tenant",
            extra={
                "endpoint": getattr(request_obj, "endpoint", "unknown"),
                "header_tenant": context.header_tenant,
                "session_tenant": context.session_tenant,
                "principal_hash": context.principal_hash,
            },
        )

        if not self._audit_sink:
            return

        try:
            session_obj = getattr(request_obj, "session", None)
            self._audit_sink.log_tenant_violation(
                user_id=getattr(session_obj, "user_id", None),
                username=getattr(session_obj, "username", None),
                ip_address=getattr(request_obj, "remote_addr", ""),
                attempted_tenant=context.header_tenant,
                allowed_tenant=context.session_tenant,
            )
        except Exception as exc:
            logger.error(
                "Failed to audit tenant header conflict",
                extra={"error": str(exc)},
            )

    def setup_tenant_context(self, req=None):
        """Resolve tenant_id once per request and cache it on request and Flask g.

        Resolution order:
          1) request.session.tenant_id (authoritative)
          2) trusted header (auth_config.tenant_id_header) when no session is present

        If a header is present and mismatches the session tenant, the session value
        wins and a warning is logged (optionally audited). Returns the resolved
        tenant_id or None.
        """
        try:
            request_obj = req or get_request()
        except Exception:
            request_obj = None

        if request_obj is None:
            return None

        existing_context = getattr(request_obj, "_tenant_context", None)
        if isinstance(existing_context, TenantContext):
            self._attach_context(request_obj, existing_context)
            self._handle_conflict(request_obj, existing_context)
            return existing_context.tenant_id

        context = self._resolver.resolve(request_obj)
        self._attach_context(request_obj, context)
        self._handle_conflict(request_obj, context)

        return context.tenant_id
```

- **Idempotency and rate limiting primitives** — Partial. The middleware stack includes an in-memory idempotency store plus global/user rate limiting primitives, but no write endpoints currently opt in.

```48:109:apps/api/http/middleware/idempotency.py
class InMemoryIdempotencyStore:
    """Thread-safe, TTL-based idempotency store."""

    def __init__(self, ttl_seconds: int = 24 * 3600) -> None:
        self._ttl_seconds = max(60, int(ttl_seconds))
        self._entries: Dict[str, IdempotencyEntry] = {}
        self._lock = threading.RLock()

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)

    def reserve(self, key: str, *, method: str, path: str, tenant_id: Optional[str]) -> Tuple[str, IdempotencyEntry]:
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            entry = self._entries.get(key)
            if entry:
                return entry.status, entry
            expires_at = now + self._ttl_seconds
            entry = IdempotencyEntry(
                status="in_progress",
                method=method,
                path=path,
                tenant_id=tenant_id,
                created_at=now,
                expires_at=expires_at,
            )
            self._entries[key] = entry
            return "reserved", entry

    def record_response(
        self,
        key: str,
        *,
        status_code: int,
        body_base64: str,
        headers: Dict[str, str],
    ) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return
            entry.status = "completed"
            entry.status_code = status_code
            entry.body_base64 = body_base64
            entry.headers = headers

    def release(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)


def _get_store() -> InMemoryIdempotencyStore:
    store = current_app.config.get("idempotency_store")
    if isinstance(store, InMemoryIdempotencyStore):
        return store
    store = InMemoryIdempotencyStore()
    current_app.config["idempotency_store"] = store
    return store
```

- **Firestore repositories** — Partial. The factory exposes telemetry, users, sessions, audit, and devices stores only; tenants, invites, idempotency keys, and other design-plan collections are absent.

```63:126:adapters/db/firestore/service_factory.py
    def get_telemetry_service(self) -> TelemetryRepository:
        """Get telemetry service instance."""
        if 'telemetry' not in self._repositories:
            self._repositories['telemetry'] = TelemetryRepository(self.client)
        return self._repositories['telemetry']

    def get_users_service(self) -> UsersRepository:
        """Get users service instance."""
        if 'users' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['users'] = UsersRepository(self.client, cache=cache)
        return self._repositories['users']

    def get_sessions_service(self) -> SessionsStore:
        """Get sessions service instance."""
        if 'sessions' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['sessions'] = SessionsStore(self.client, cache=cache)
        return self._repositories['sessions']

    def get_audit_service(self) -> AuditLogStore:
        """Get audit service instance."""
        if 'audit' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['audit'] = AuditLogStore(self.client, cache=cache)
        return self._repositories['audit']

    def get_devices_service(self) -> DevicesStore:
        """Get devices service instance."""
        if 'devices' not in self._repositories:
            cache = self._resolve_cache_client()
            self._repositories['devices'] = DevicesStore(self.client, cache=cache)
        return self._repositories['devices']

    def get_all_repositories(self) -> Dict[str, Any]:
        """Get all repository instances."""
        return {
            'telemetry': self.get_telemetry_repository(),
            'users': self.get_users_repository(),
            'sessions': self.get_sessions_repository(),
            'audit': self.get_audit_repository(),
            'devices': self.get_devices_repository()
        }
```

- **Cross-service authentication** — Partial. Service JWT issuance/verification supports API→auth interactions, but there is no auth-service minted provisioning token or API nonce store yet, leaving signup/invite/device workflows unimplemented.

## 2. Implementation Roadmap

### Step 0 — Shared Contracts & Configuration *(complete)*

- ✅ Typed dataclass schemas now live under `apps/api/http/schemas/` and `apps/auth_service/http/schemas/`, providing symmetric validation helpers for org signup, invite, and device registration flows. Shared utilities were hoisted into `app_platform/schemas` to keep coercion rules aligned between services.
- ✅ Cross-service contracts (`OrgSignupFeatureFlag`, provisioning JWT claims, request headers, enums for tenant/member/invite/device state) are centralized in `app_platform/contracts/orgs.py`, eliminating duplicated literals.
- ✅ Configuration surfaces were extended across `app_platform/config/auth.py`, `config/auth*.env`, and `ServerConfig.org_flows` to expose feature toggles, provisioning key metadata, invite quotas, CAPTCHA settings, idempotency TTLs, and replay-cache budgets. Runtime wiring now publishes these flags into both API and auth-service Flask apps for feature gating.
- ✅ Firestore domain support landed via new models in `adapters/db/firestore/models.py` and repository adapters (`tenant_store.py`, `member_store.py`, `invite_store.py`, `idempotency_store.py`) registered with the `FirestoreServiceFactory`, giving upcoming steps transactional primitives for tenant onboarding.

### Step 1 — Auth-Service Enhancements *(complete)*

- ✅ Provisioning support landed via `ProvisioningTokenService` and the new `/auth/orgs/provision` endpoint. Requests require a validated service JWT, tokens are signed with RS256 keys loaded from `AuthConfig`, carry tenant/admin metadata, enforce `nonce` + `jti` uniqueness with the replay cache, and emit structured audit logs. Services are injected per-request so only requests behind `ORG_SIGNUP_V2` touch the feature.
- ✅ Verification webhooks are handled at `/auth/events/email-verified`. Payloads must present a valid HMAC signature (derived from `AUTH0_WEBHOOK_SECRET`) before they are parsed, deduped via `ReplayCache`, and forwarded to the API using short-lived service JWTs. Transport leverages a shared HTTP session with configurable timeout/backoff, and duplicates return 202 to drive idempotent Auth0 Actions.
- ✅ Invite issuance moved into `InviteService` powering `/auth/invite`. Calls must authenticate with a service JWT, invites hash secret material, persist structured metadata in Firestore, respect tenant sliding-window quotas, and (when Auth0 Management credentials are present) block the user + patch `app_metadata` through a breaker-guarded client. Responses surface the one-time token for downstream delivery workers.

### Step 2 — API Org Signup Flow *(complete)*

- ✅ Added `apps/api/http/org_routes.py` exposing `/orgs/signup` and `/auth/events/email-verified`, feature-gated via `org_signup_v2_enabled`. `router.register_routes` now registers the blueprint only when the flag is set, and `apps/api/main.py` seeds the flag/config on app start.
- ✅ Signup handler chains `enforce_idempotency`, CAPTCHA verification (`app_platform/security/captcha.py`), provisioning JWT validation, and a Firestore transaction that creates the tenant document, admin placeholder, counters, audit log entry, and an `OutboxEvent` seeded through the new repository (`adapters/db/firestore/outbox_store.py`).
- ✅ Durable idempotency persistence leverages the Firestore `IdempotencyKeyRepository` for request hashing and replay-safe 202 responses, while provisioning JWTs rely on `load_service_keyset_from_env` + `ReplayCache` to dedupe `jti`/`nonce` values and interoperate with the auth-service callbacks.

### Step 3 — Admin Verification & Invite Workflow *(complete)*

- ✅ Email verification webhook now triggers `_activate_verified_admin` transactional flow in `apps/api/http/org_routes.py`, promoting the pending admin, updating tenant counters, emitting audit/outbox records, and tolerating replays.
- ✅ Added `POST /tenants/<tenantId>/users/invite` with admin-only auth, tenant isolation, signed request JWT validation, per-tenant rate limiting, Auth-service orchestration, Firestore member/sentinel persistence, audit logging, and resilient outbox enqueueing.
- ✅ Implemented `/auth/accept-invite` to validate tokens, handle expiration/conflicts, finalize member activation within Firestore, emit audit/outbox events, and mint short-lived acceptance JWTs for downstream onboarding.

### Step 4 — Device Provisioning Lifecycle *(complete)*

- ✅ Implemented `/tenants/{tenantId}/devices` (POST/GET) and `/tenants/{tenantId}/devices/{deviceId}` (DELETE) in `apps/api/http/org_routes.py` with stacked `require_auth`, `enforce_tenant_isolation`, `require_device_access`, and `enforce_idempotency` decorators to guard multi-tenant access.
- ✅ Device registration allocates credentials via the new `DeviceCredentialService` (`apps/api/services/device_credentials.py`) backed by `SecretManagerAdapter`, storing only credential references, scheduling rotation outbox events, and capturing audit trails.
- ✅ Soft delete path updates counters, emits `tenant.device_deleted` / credential revocation outbox events, and preserves replay-safe status codes while leaving revocation to asynchronous workers.
- 🚧 Unit/integration coverage for the device lifecycle is planned for a follow-up iteration.

### Step 5 — Observability, Reliability, and Security Hardening

- Expand structured logging to include tenant/user/trace metadata for new endpoints and emit metrics (`invite_created`, `tenant_signup_latency`, etc.) via `logging_lib` exporters.
- Implement `/readyz` checks for Firestore, Redis nonce store, Auth0 JWKS freshness, and service token key health in both services.
- Extend rate limiting configuration to include signup/invite/device policies and integrate CAPTCHA verification with retry/backoff paths.

### Step 6 — Testing, QA, and Rollout

- Author unit tests for validators, middleware, and Firestore transactions; add integration tests in `tests/integration/org_signup` covering signup → verify → invite → accept → device flows using emulators.
- Provide contract tests ensuring inter-service JWT validation, nonce replay prevention, and cross-tenant access denial along with load and chaos tests.
- Document rollout steps, feature-flag management, and failure playbooks in `docs/user_flows/organization_creation_design_plan.md` and update CI pipelines to seed required secrets/emulators.


