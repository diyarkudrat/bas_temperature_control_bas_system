from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Mapping, Optional

from jose import jwk
from jose.exceptions import JWKError

try:  # stdlib HTTP with timeout
    from urllib.request import urlopen
    from urllib.error import URLError, HTTPError
except Exception:  # pragma: no cover
    urlopen = None  # type: ignore
    URLError = Exception  # type: ignore
    HTTPError = Exception  # type: ignore

from ..circuit_breaker import CircuitBreaker


class _JwksCache:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = int(ttl_seconds)
        self._keys: Dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def is_expired(self) -> bool:
        with self._lock:
            if self._fetched_at <= 0:
                return True
            return (time.time() - self._fetched_at) >= self._ttl

    def get(self, kid: str) -> Optional[Any]:
        with self._lock:
            return self._keys.get(kid)

    def set_all(self, kid_to_key: Dict[str, Any]) -> None:
        with self._lock:
            self._keys = dict(kid_to_key)
            self._fetched_at = time.time()

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()
            self._fetched_at = 0.0

    def age_seconds(self) -> float:
        with self._lock:
            if self._fetched_at <= 0:
                return float("inf")
            return max(0.0, time.time() - self._fetched_at)


class JWKSClient:
    """Encapsulate JWKS fetch, cache and preparation behind a breaker."""

    def __init__(self, *, url: str, timeout_s: int, cache_ttl_s: int, breaker: CircuitBreaker) -> None:
        self._url = url
        self._timeout_s = int(timeout_s)
        self._cache = _JwksCache(int(cache_ttl_s))
        self._breaker = breaker

    def get_key(self, kid: str) -> Optional[Any]:
        return self._cache.get(kid)

    def set_all(self, kid_to_key: Dict[str, Any]) -> None:
        self._cache.set_all(kid_to_key)

    def age_seconds(self) -> float:
        return self._cache.age_seconds()

    def invalidate(self) -> None:
        self._cache.clear()

    def fetch_raw(self) -> Dict[str, Any]:
        if urlopen is None:
            raise ValueError("HTTP client unavailable for JWKS fetch")

        def _net_call():
            with urlopen(self._url, timeout=self._timeout_s) as resp:
                body = resp.read()
                data = json.loads(body.decode("utf-8"))
                if not isinstance(data, dict) or "keys" not in data:
                    raise ValueError("malformed JWKS document")
                return data

        try:
            return self._breaker.wrap_call(_net_call, max_tries=3)
        except (URLError, HTTPError) as exc:
            raise ValueError(f"failed to fetch JWKS: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("failed to parse JWKS JSON") from exc

    def prepare_keys(self, jwks: Mapping[str, Any]) -> Dict[str, Any]:
        kid_to_key: Dict[str, Any] = {}
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS keys must be a list")
        for key_dict in keys:
            if not isinstance(key_dict, dict):
                continue
            kty = key_dict.get("kty")
            alg = key_dict.get("alg")
            kid = key_dict.get("kid")
            use = key_dict.get("use")
            if kty != "RSA" or (alg and alg != "RS256"):
                continue
            if use and use != "sig":
                continue
            if not kid:
                continue
            try:
                key = jwk.construct(key_dict, algorithm="RS256")
            except (JWKError, Exception):
                n = key_dict.get("n")
                e = key_dict.get("e")
                if not (isinstance(n, str) and isinstance(e, str)):
                    continue
                try:
                    key = jwk.construct({"kty": "RSA", "n": n, "e": e}, algorithm="RS256")
                except Exception:
                    continue
            kid_to_key[str(kid)] = key
        if not kid_to_key:
            raise ValueError("no usable RSA keys in JWKS")
        return kid_to_key


