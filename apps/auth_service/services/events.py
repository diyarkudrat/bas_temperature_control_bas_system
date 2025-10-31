"""Webhook processing and API forwarding for verification events."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
from typing import Mapping, Optional
from urllib.parse import urljoin

import requests

from app_platform.security import ReplayCache, ServiceKeySet, ServiceTokenError, issue_service_jwt

from apps.auth_service.http.schemas.events import EmailVerifiedEvent

from .exceptions import (
    DuplicateEventError,
    ServiceConfigurationError,
    UnauthorizedRequestError,
    UpstreamServiceError,
)

logger = logging.getLogger(__name__)


class EmailVerificationService:
    """Validate Auth0 verification events and forward to the API service."""

    def __init__(
        self,
        *,
        api_base_url: str,
        http_client: requests.Session,
        replay_cache: ReplayCache,
        signing_keyset: ServiceKeySet,
        signing_subject: str,
        signing_audience: Optional[str],
        signing_issuer: Optional[str],
        signing_scopes: tuple[str, ...] = (),
        request_timeout_s: float = 5.0,
        ttl_seconds: int = 60,
        webhook_secret: Optional[str] = None,
        signature_header: str = "X-Auth0-Signature",
    ) -> None:
        if ttl_seconds > 60:
            ttl_seconds = 60

        self._api_base_url = api_base_url.rstrip("/")
        self._http_client = http_client
        self._replay_cache = replay_cache
        self._keyset = signing_keyset
        self._subject = signing_subject or "auth.events.email_verified"
        self._audience = signing_audience
        self._issuer = signing_issuer
        self._scopes = signing_scopes
        self._timeout = max(1.0, request_timeout_s)
        self._ttl = max(1, ttl_seconds)
        self._webhook_secret = webhook_secret.strip() if webhook_secret else None
        self._signature_header = signature_header

        if not self._api_base_url:
            raise ServiceConfigurationError("API base URL must be provided for verification forwarding")

    def validate_signature(self, headers: Mapping[str, str], body: bytes) -> None:
        if not self._webhook_secret:
            raise ServiceConfigurationError("Auth0 webhook secret not configured")

        presented = headers.get(self._signature_header) or headers.get(self._signature_header.lower())
        if not presented:
            raise UnauthorizedRequestError("Missing webhook signature")

        # Support formats like "sha256=..." or raw base64/hex digests.
        if presented.startswith("sha256="):
            presented = presented[len("sha256=") :]

        secret_bytes = self._webhook_secret.encode("utf-8")
        digest = hmac.new(secret_bytes, body, hashlib.sha256).digest()
        expected_b64 = base64.b64encode(digest).decode("ascii")
        expected_hex = digest.hex()

        if not _constant_time_compare(presented, expected_b64) and not _constant_time_compare(presented, expected_hex):
            raise UnauthorizedRequestError("Invalid webhook signature")

    def process_email_verified(self, event: EmailVerifiedEvent) -> None:
        replay_id = f"email-verified:{event.event_id}:{event.auth0_user_id}"
        if not self._replay_cache.check_and_store(replay_id, expires_at=int(time.time()) + 2 * self._ttl):
            raise DuplicateEventError("Verification event already processed")

        token = self._mint_request_token(event.context_claims())

        url = urljoin(self._api_base_url + "/", "auth/events/email-verified")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Event-ID": event.event_id,
            "X-Auth0-User": event.auth0_user_id,
        }

        try:
            response = self._http_client.post(url, json=event.to_forward_payload(), headers=headers, timeout=self._timeout)
        except requests.RequestException as exc:  # pragma: no cover - network failure
            logger.error("Failed to forward verification event", extra={"event_id": event.event_id, "error": str(exc)})
            raise UpstreamServiceError("API forwarding failed") from exc

        if response.status_code >= 500:
            logger.error(
                "API service error forwarding verification event",
                extra={"event_id": event.event_id, "status": response.status_code},
            )
            raise UpstreamServiceError(f"API service returned {response.status_code}")

        if response.status_code >= 400:
            logger.warning(
                "API service rejected verification event",
                extra={"event_id": event.event_id, "status": response.status_code, "body": response.text},
            )
            raise UpstreamServiceError(f"API rejected event with {response.status_code}")

        logger.info(
            "Verification event forwarded",
            extra={
                "event_id": event.event_id,
                "tenant_id": event.tenant_id,
                "auth0_user_id": event.auth0_user_id,
                "api_status": response.status_code,
            },
        )

    def _mint_request_token(self, additional_claims: Mapping[str, str]) -> str:
        try:
            issued = issue_service_jwt(
                self._keyset,
                subject=self._subject,
                audience=self._audience or None,
                issuer=self._issuer or None,
                ttl_seconds=self._ttl,
                scope=self._scopes or None,
                additional_claims=additional_claims,
            )
        except ServiceTokenError as exc:
            raise ServiceConfigurationError(f"Failed to mint request JWT: {exc}") from exc
        return issued.token


def _constant_time_compare(presented: str, expected: str) -> bool:
    try:
        presented_bytes = presented.encode("ascii")
        expected_bytes = expected.encode("ascii")
    except Exception:
        return False
    return hmac.compare_digest(presented_bytes, expected_bytes)


