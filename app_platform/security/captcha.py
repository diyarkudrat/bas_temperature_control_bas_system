"""CAPTCHA verification helpers for public-facing endpoints.

This module centralizes CAPTCHA verification so HTTP handlers can defer the
provider-specific details to a single, testable component. The design keeps
transport concerns (HTTP calls, secrets resolution) encapsulated and exposes a
simple interface that returns structured metadata for observability.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, MutableMapping, Optional

import requests

logger = logging.getLogger(__name__)


class CaptchaVerificationError(Exception):
    """Raised when a CAPTCHA challenge fails verification."""


@dataclass(slots=True, frozen=True)
class CaptchaConfig:
    """Configuration describing how to verify CAPTCHA challenges."""

    provider: str
    secret_handle: str
    min_score: float = 0.5
    site_key: Optional[str] = None


class CaptchaVerifier:
    """Verify CAPTCHA tokens against supported providers."""

    _RECAPTCHA_ENDPOINT = "https://www.google.com/recaptcha/api/siteverify"

    def __init__(
        self,
        config: CaptchaConfig,
        *,
        http_client: Optional[requests.Session] = None,
        request_timeout_s: float = 3.0,
    ) -> None:
        """Initialize the CaptchaVerifier."""

        provider = (config.provider or "").strip().lower()

        if not provider:
            raise CaptchaVerificationError("captcha provider is not configured")

        self._provider = provider # Provider name
        self._secret = _resolve_secret(config.secret_handle) # Secret handle
        self._min_score = max(0.0, min(config.min_score, 1.0)) # Minimum score
        self._http = http_client or requests.Session() # HTTP client
        self._timeout = max(1.0, request_timeout_s) # Request timeout
        self._site_key = config.site_key # Site key

    def verify(self, token: Optional[str], *, remote_addr: Optional[str] = None) -> Mapping[str, Any]:
        """Verify the provided CAPTCHA token.

        Returns provider-specific metadata when verification succeeds. Raises
        :class:`CaptchaVerificationError` when verification fails or the token
        is missing.
        """

        if self._provider == "disabled":
            logger.debug("CAPTCHA provider disabled; skipping verification")

            result: dict[str, Any] = {"provider": self._provider, "skipped": True}

            return MappingProxyType[str, Any](result)

        normalized_token = (token or "").strip()
        if not normalized_token:
            raise CaptchaVerificationError("captcha token is required")

        if self._provider == "recaptcha":
            return self._verify_recaptcha(normalized_token, remote_addr=remote_addr)

        raise CaptchaVerificationError(f"unsupported CAPTCHA provider '{self._provider}'")

    # ------------------------------------------------------------------
    # Provider handlers
    # ------------------------------------------------------------------

    def _verify_recaptcha(self, token: str, *, remote_addr: Optional[str]) -> Mapping[str, Any]:
        """Verify a reCAPTCHA token."""

        payload: MutableMapping[str, str] = {"secret": self._secret, "response": token}

        if remote_addr:
            payload["remoteip"] = remote_addr

        try:
            response = self._http.post(self._RECAPTCHA_ENDPOINT, data=payload, timeout=self._timeout)
        except requests.RequestException as exc:  # noqa: BLE001 - surface network issues upstream
            logger.error("reCAPTCHA verification failed", exc_info=exc)
            raise CaptchaVerificationError("captcha verification unavailable") from exc

        try:
            data = response.json()
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive guard
            logger.warning("reCAPTCHA returned non-JSON payload", extra={"status_code": response.status_code})
            raise CaptchaVerificationError("captcha verification failed") from exc

        success = bool(data.get("success"))
        score = float(data.get("score", 0.0)) if "score" in data else None
        action = data.get("action")

        logger.debug(
            "reCAPTCHA verification result",
            extra={
                "success": success,
                "score": score,
                "action": action,
                "status_code": response.status_code,
            },
        )

        if not success:
            error_codes = data.get("error-codes", [])
            raise CaptchaVerificationError(
                "captcha verification failed",
            ) from None if not error_codes else CaptchaVerificationError(
                f"captcha verification failed: {', '.join(error_codes)}"
            )

        if score is not None and score < self._min_score:
            raise CaptchaVerificationError("captcha score below minimum threshold")

        result: dict[str, Any] = {
            "provider": self._provider,
            "score": score,
            "action": action,
        }

        return MappingProxyType[str, Any](result)


def _resolve_secret(handle: str) -> str:
    """Resolve a secret handle to a secret value."""

    normalized = (handle or "").strip()
    if not normalized:
        raise CaptchaVerificationError("captcha secret handle is not configured")

    if normalized.startswith("env://"):
        env_name = normalized[6:].strip()

        if not env_name:
            raise CaptchaVerificationError("captcha secret env handle is empty")

        value = os.getenv(env_name)
        if not value:
            raise CaptchaVerificationError(f"environment variable '{env_name}' is not set for captcha secret")

        return value.strip()

    if normalized.startswith("file://"):
        path = normalized[7:].strip()
        
        if not path:
            raise CaptchaVerificationError("captcha secret file handle is empty")
        try:
            with open(path, "r", encoding="utf-8") as handle_obj:
                return handle_obj.read().strip()
        except FileNotFoundError as exc:  # pragma: no cover - configuration issue
            raise CaptchaVerificationError(f"captcha secret file not found at '{path}'") from exc

    if normalized.startswith("projects/"):
        raise CaptchaVerificationError(
            "Secret Manager handles are not supported yet for captcha verification",
        )

    return normalized


__all__ = [
    "CaptchaConfig",
    "CaptchaVerificationError",
    "CaptchaVerifier",
]


