"""Lightweight Auth0 Management API client with rate limiting and breaker."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import urljoin, urlparse

import requests

from app_platform.config.auth0_configs import Auth0MgmtConfig
from app_platform.utils.circuit_breaker import CircuitBreaker

from .exceptions import UpstreamServiceError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _TokenInfo:
    token: str
    expires_at: float


class _TokenBucket:
    def __init__(self, *, rate: float, capacity: int) -> None:
        self._rate = max(rate, 0.1)
        self._capacity = max(capacity, 1)
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout_s: float = 1.0) -> bool:
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self._last_refill)
        if elapsed <= 0.0:
            return
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now


class Auth0ManagementClient:
    """Thin wrapper around Auth0 Management API with retries and breaker."""

    def __init__(
        self,
        config: Auth0MgmtConfig,
        session: requests.Session,
        *,
        breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self._config = config
        self._session = session
        self._breaker = breaker or CircuitBreaker()
        self._token: Optional[_TokenInfo] = None
        self._token_lock = threading.RLock()
        self._bucket = _TokenBucket(rate=config.rps or 5.0, capacity=config.burst or 10)
        self._base_url = self._normalize_base_url(config.base_url)
        self._token_url = self._derive_token_url(self._base_url)

    @staticmethod
    def _normalize_base_url(base_url: Optional[str]) -> Optional[str]:
        if not base_url:
            return None
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            logger.warning("Invalid Auth0 base URL provided: %s", base_url)
            return None
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path:
            normalized = urljoin(normalized + "/", parsed.path.lstrip("/"))
        if not normalized.endswith("/"):
            normalized = f"{normalized}/"
        return normalized

    @staticmethod
    def _derive_token_url(base_url: Optional[str]) -> Optional[str]:
        if not base_url:
            return None
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}/oauth/token"

    @property
    def enabled(self) -> bool:
        return all(
            [
                self._config.client_id,
                self._config.client_secret,
                self._config.audience,
                self._base_url,
                self._token_url,
            ]
        )

    def block_user(self, user_id: str, *, reason: Optional[str] = None) -> None:
        payload: dict[str, Any] = {"blocked": True}
        if reason:
            payload.setdefault("app_metadata", {})
            payload["app_metadata"]["blocked_reason"] = reason
        self._patch_user(user_id, payload)

    def unblock_user(self, user_id: str) -> None:
        self._patch_user(user_id, {"blocked": False})

    def update_app_metadata(self, user_id: str, metadata: Mapping[str, Any]) -> None:
        self._patch_user(user_id, {"app_metadata": dict(metadata)})

    def _patch_user(self, user_id: str, payload: Mapping[str, Any]) -> None:
        if not self.enabled:
            logger.debug("Auth0 management client disabled; skipping user patch")
            return
        path = f"api/v2/users/{user_id}"
        self._request("PATCH", path, json=payload)

    # --------------------- HTTP helpers ---------------------
    def _ensure_token(self) -> str:
        with self._token_lock:
            if self._token and self._token.expires_at - time.time() > 30:
                return self._token.token
            if not self.enabled:
                raise UpstreamServiceError("Auth0 management client not fully configured")
            logger.debug("Refreshing Auth0 management API token")
            data = {
                "grant_type": "client_credentials",
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "audience": self._config.audience,
            }
            response = self._session.post(
                self._token_url,
                json=data,
                timeout=self._config.timeout_s,
            )
            if response.status_code >= 400:
                raise UpstreamServiceError(
                    f"Auth0 token request failed ({response.status_code})",
                )
            body = response.json()
            access_token = body.get("access_token")
            expires_in = int(body.get("expires_in", 300))
            if not access_token:
                raise UpstreamServiceError("Auth0 token response missing access_token")
            self._token = _TokenInfo(token=access_token, expires_at=time.time() + max(expires_in, 60))
            return access_token

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        assert path, "path required"
        if not path.startswith("http"):
            if not self._base_url:
                raise UpstreamServiceError("Auth0 base URL not configured")
            url = urljoin(self._base_url, path)
        else:
            url = path

        backoff = self._config.backoff_base_ms / 1000.0
        max_backoff = self._config.backoff_max_ms / 1000.0
        attempts = max(1, self._config.retries + 1)

        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            if not self._bucket.acquire(timeout_s=2.0):
                logger.debug("Auth0 management client throttled; waiting for capacity")
                time.sleep(0.1)
                continue

            if not self._breaker.allow_call():
                raise UpstreamServiceError("Auth0 management breaker open")

            try:
                token = self._ensure_token()
            except Exception as exc:  # noqa: BLE001
                self._breaker.on_failure(exc)
                last_error = exc
                break

            headers = kwargs.pop("headers", {}) or {}
            headers.setdefault("Authorization", f"Bearer {token}")
            headers.setdefault("Content-Type", "application/json")

            try:
                response = self._session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self._config.timeout_s,
                    **kwargs,
                )
            except requests.RequestException as exc:  # pragma: no cover - network failure
                self._breaker.on_failure(exc)
                last_error = exc
                if attempt >= attempts:
                    break
                time.sleep(min(max_backoff, backoff))
                backoff = min(max_backoff, backoff * 2 or 0.05)
                continue

            if response.status_code == 401:
                with self._token_lock:
                    self._token = None
                if attempt >= attempts:
                    self._breaker.on_failure(RuntimeError("auth0_unauthorized"))
                    raise UpstreamServiceError("Auth0 management unauthorized")
                self._breaker.on_failure(RuntimeError("auth0_unauthorized"))
                continue

            if response.status_code >= 500:
                self._breaker.on_failure(RuntimeError(f"auth0_{response.status_code}"))
                last_error = UpstreamServiceError(f"Auth0 error {response.status_code}")
                if attempt >= attempts:
                    break
                time.sleep(min(max_backoff, backoff))
                backoff = min(max_backoff, backoff * 2 or 0.05)
                continue

            if response.status_code >= 400:
                self._breaker.on_failure(RuntimeError(f"auth0_{response.status_code}"))
                raise UpstreamServiceError(
                    f"Auth0 management request failed ({response.status_code})",
                )

            self._breaker.on_success()
            if response.content:
                try:
                    return response.json()
                except ValueError:
                    return response.text
            return None

        raise UpstreamServiceError(f"Auth0 management request failed: {last_error}")


