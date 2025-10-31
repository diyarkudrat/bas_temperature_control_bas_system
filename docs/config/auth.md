# Auth Configuration Reference

This document captures the configuration knobs introduced for the organization
creation flows. All values can be supplied via environment variables (preferred
for secrets) or `configs/app/auth_config.json` when running locally.

## Feature Toggles

- `ORG_SIGNUP_V2` — enables the new organization signup HTTP surface.
- `DEVICE_RBAC_ENFORCEMENT` — enforces device lifecycle routes to respect the
  RBAC metadata in access tokens.

Both toggles default to `false` and should roll out progressively (dev →
staging → prod). They are also available inside `AuthConfig` as
`org_signup_v2_enabled` and `device_rbac_enforcement` for runtime checks.

## Provisioning Tokens

- `ORG_SIGNUP_SIGNING_KEY_ID` — identifier for the asymmetric key used to mint
  provisioning JWTs. Required when `ORG_SIGNUP_V2` is enabled.
- `ORG_SIGNUP_PRIVATE_KEY_SECRET` — Secret Manager handle or PEM material used
  to sign provisioning tokens. For production, supply a Secret Manager URI
  (e.g. `projects/<project>/secrets/<name>/versions/latest`).
- `ORG_SIGNUP_JWT_TTL_SECONDS` — TTL for provisioning tokens issued by the
  auth-service (default `60`). Values outside 30-300 seconds raise warnings.
- `REQUEST_JWT_REPLAY_TTL_SECONDS` — TTL applied to nonce replay cache used to
  dedupe signed request JWTs (default `120`).
- `AUTH0_WEBHOOK_SECRET` — shared secret used to verify Auth0 email verification
  webhook signatures. Required for `/auth/events/email-verified` to accept
  events.

## Invite & Tenant Controls

- `INVITE_MAX_PER_TENANT` — soft quota per tenant for invites issued in the
  sliding window defined below (default `20`).
- `INVITE_QUOTA_WINDOW_MINUTES` — window size for invite quotas (default `60`).
- `INVITE_TTL_HOURS` — invite expiry horizon (default `72`).
- `DEFAULT_DEVICE_QUOTA` — default maximum devices per tenant when provisioning
  a new organization (default `100`).
- `IDEMPOTENCY_TTL_HOURS` — TTL for durable idempotency entries stored in
  Firestore (default `24`).

## CAPTCHA Configuration

- `CAPTCHA_PROVIDER` — provider identifier (e.g. `recaptcha`).
- `CAPTCHA_SITE_KEY` — public key presented to clients.
- `CAPTCHA_SECRET_HANDLE` — Secret Manager handle to verify challenges.
- `CAPTCHA_MIN_SCORE` — minimum acceptable score when using score-based
  providers (default `0.5`).

All CAPTCHA fields are optional; when a provider is set a secret handle should
also be configured to avoid startup warnings.

## Accessing Values

At runtime both the API and auth-service expose:

- `request.auth_config.org_signup_v2_enabled`
- `request.auth_config.device_rbac_enforcement`
- `request.auth_config.invite_quota_per_tenant`
- `request.auth_config.captcha_provider`

Additionally, `ServerConfig.org_flows` mirrors the same settings when
service-wide coordination is required.


