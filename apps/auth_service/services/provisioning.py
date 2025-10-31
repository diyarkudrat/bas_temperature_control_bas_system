"""Provisioning token issuance logic for organization onboarding."""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Mapping, Optional

from app_platform.config.auth import AuthConfig
from app_platform.contracts import PROVISIONING_JWT, ProvisioningClaims
from app_platform.security import (
    ReplayCache,
    ServiceKey,
    ServiceKeySet,
    ServiceTokenError,
    issue_service_jwt,
    load_replay_cache_from_env,
)

from apps.auth_service.http.schemas.org import (
    OrgProvisioningRequest,
    OrgProvisioningResponse,
)

from .exceptions import ServiceConfigurationError

logger = logging.getLogger(__name__)


def _normalize_secret_value(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ServiceConfigurationError("Provisioning private key material is empty")
    return normalized.replace("\\n", "\n")


def _resolve_private_key(secret_hint: Optional[str]) -> str:
    if secret_hint is None:
        raise ServiceConfigurationError("Provisioning private key secret not configured")

    hint = secret_hint.strip()
    if not hint:
        raise ServiceConfigurationError("Provisioning private key secret not configured")

    if hint.startswith("env://"):
        env_name = hint[6:].strip()
        secret_value = os.getenv(env_name)
        if not secret_value:
            raise ServiceConfigurationError(f"Environment variable '{env_name}' missing for provisioning key")
        return _normalize_secret_value(secret_value)

    if hint.startswith("file://"):
        path = hint[7:].strip()
        if not path:
            raise ServiceConfigurationError("Provisioning key file path is empty")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return _normalize_secret_value(handle.read())
        except FileNotFoundError as exc:  # pragma: no cover - configuration error
            raise ServiceConfigurationError(f"Provisioning key file not found at '{path}'") from exc

    if hint.startswith("projects/"):
        raise ServiceConfigurationError(
            "Secret Manager references are not yet supported; provide env:// or file:// handle",
        )

    return _normalize_secret_value(hint)


class ProvisioningTokenService:
    """Mint short-lived provisioning JWTs for the API service."""

    def __init__(
        self,
        config: AuthConfig,
        *,
        replay_cache: Optional[ReplayCache] = None,
        replay_cache_prefix: str = "ORG_SIGNUP_JWT",
    ) -> None:
        self._config = config
        self._ttl_seconds = max(1, min(int(config.provisioning_jwt_ttl_seconds or 60), 60))
        self._keyset = self._build_keyset(config)
        self._replay_cache = replay_cache or load_replay_cache_from_env(
            prefix=replay_cache_prefix,
            namespace="org-signup",
            default_ttl_seconds=max(self._ttl_seconds * 2, config.replay_cache_ttl_seconds or 120),
            default_max_entries=2048,
        )

    @staticmethod
    def _build_keyset(config: AuthConfig) -> ServiceKeySet:
        key_id = (config.provisioning_key_id or "org-signup").strip()
        if not key_id:
            raise ServiceConfigurationError("Provisioning signing key id is required")

        try:
            private_key = _resolve_private_key(config.provisioning_private_key_secret)
        except ServiceConfigurationError:
            logger.exception("Failed to resolve provisioning private key")
            raise

        try:
            service_key = ServiceKey(kid=key_id, alg="RS256", private_key=private_key)
            return ServiceKeySet([service_key], default_kid=key_id, allowed_algorithms=("RS256",))
        except ServiceTokenError as exc:
            raise ServiceConfigurationError(f"Invalid provisioning key configuration: {exc}") from exc

    @property
    def enabled(self) -> bool:
        return bool(self._config.org_signup_v2_enabled)

    def mint(
        self,
        payload: OrgProvisioningRequest,
        *,
        request_id: Optional[str] = None,
        remote_addr: Optional[str] = None,
    ) -> OrgProvisioningResponse:
        if not self.enabled:
            raise ServiceConfigurationError("Organization signup feature flag disabled")

        claims_payload = ProvisioningClaims(
            tenant_name=payload.tenant_name,
            admin_email=payload.admin_email,
            tenant_slug=payload.tenant_slug,
            plan=payload.plan,
        ).to_claims()

        additional_claims: dict[str, Mapping[str, Optional[str]] | Mapping[str, object]] = {
            PROVISIONING_JWT.tenant_claim: claims_payload,
        }

        if payload.metadata:
            try:
                additional_claims["metadata"] = dict(payload.metadata)
            except Exception:  # pragma: no cover - defensive copy
                additional_claims["metadata"] = {"_error": "metadata_unserializable"}

        try:
            issued = issue_service_jwt(
                self._keyset,
                subject=PROVISIONING_JWT.subject,
                audience=PROVISIONING_JWT.audience,
                issuer=PROVISIONING_JWT.issuer,
                ttl_seconds=self._ttl_seconds,
                nonce=payload.nonce,
                additional_claims=additional_claims,
            )
        except ServiceTokenError as exc:
            raise ServiceConfigurationError(f"Failed to issue provisioning JWT: {exc}") from exc

        replay_identifier = f"{issued.claims.get('iss')}:{issued.claims.get('sub')}:{issued.claims.get('jti')}"
        try:
            self._replay_cache.check_and_store(replay_identifier, expires_at=issued.expires_at)
        except Exception:  # pragma: no cover - best effort cache write
            logger.warning("Failed to record provisioning JWT in replay cache", extra={"jti": issued.claims.get("jti")})

        email_hash = hashlib.sha256(payload.admin_email.encode("utf-8")).hexdigest()[:12]
        logger.info(
            "Provisioning JWT minted",
            extra={
                "tenant_name": payload.tenant_name,
                "admin_email_hash": email_hash,
                "request_id": request_id,
                "remote_addr": remote_addr,
                "ttl_seconds": self._ttl_seconds,
                "kid": issued.headers.get("kid"),
            },
        )

        return OrgProvisioningResponse(
            provisioning_jwt=issued.token,
            expires_in_seconds=self._ttl_seconds,
        )


