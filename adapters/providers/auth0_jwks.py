from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Mapping, Optional

from jose import jwk  # type: ignore[import]
from jose.exceptions import JWKError  # type: ignore[import]

try:  # stdlib HTTP with timeout
    from urllib.request import urlopen
    from urllib.error import URLError, HTTPError
except Exception:  # pragma: no cover
    urlopen = None  # type: ignore
    URLError = Exception  # type: ignore
    HTTPError = Exception  # type: ignore

from app_platform.utils.circuit_breaker import CircuitBreaker


class _JwksCache:
    """Cache for JWKS keys with TTL and thread-safety.


    Internal-only utility. Uses a monotonic clock for TTL correctness.
    """


    def __init__(self, ttl_seconds: int) -> None:
        """Initialize the cache with a TTL (seconds)."""

        if ttl_seconds is None or ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be a positive integer, got {ttl_seconds}")

        self._ttl = int(ttl_seconds) # TTL in seconds
        self._keys: Dict[str, Any] = {} # JWKS keys by KID
        self._fetched_at_monotonic: float = 0.0 # last fetch time (monotonic)
        self._lock = threading.Lock() # lock for thread safety


    def _is_expired(self) -> bool:
        """Return True if the cache is empty or past TTL."""

        with self._lock:
            if self._fetched_at_monotonic <= 0:
                return True
            
            return (time.monotonic() - self._fetched_at_monotonic) >= self._ttl


    def _get(self, kid: str) -> Optional[Any]:
        """Return the JWKS key for KID if present, else None."""

        if not kid or not isinstance(kid, str):
            raise ValueError(f"kid must be a non-empty string, got {kid}")

        with self._lock:
            return self._keys.get(kid)


    def _set_all(self, kid_to_key: Dict[str, Any]) -> None:
        """Replace the cache with the provided KID→key mapping."""
        
        if not kid_to_key or not isinstance(kid_to_key, dict):
            raise ValueError(f"kid_to_key must be a non-empty dictionary, got {kid_to_key}")

        with self._lock:
            # copy to detach from caller's dict
            self._keys = dict[str, Any](kid_to_key)
            self._fetched_at_monotonic = time.monotonic()


    def _clear(self) -> None:
        """Clear the cache contents and reset age."""
        
        with self._lock:
            self._keys.clear()
            self._fetched_at_monotonic = 0.0


    def _age_seconds(self) -> float:
        """Return elapsed seconds since last fetch, or inf if never populated."""
        
        with self._lock:
            if self._fetched_at_monotonic <= 0:
                return float("inf")
            
            return max(0.0, time.monotonic() - self._fetched_at_monotonic)


class JWKSClient:
    """Encapsulate JWKS fetch, cache and preparation behind a breaker."""

    def __init__(self, *, url: str, timeout_s: int, cache_ttl_s: int, breaker: CircuitBreaker) -> None:
        """Initialize the JWKS client."""

        if not url or not isinstance(url, str):
            raise ValueError(f"url must be a non-empty string, got {url}")
        if not timeout_s or not isinstance(timeout_s, int):
            raise ValueError(f"timeout_s must be a positive integer, got {timeout_s}")
        if not cache_ttl_s or not isinstance(cache_ttl_s, int):
            raise ValueError(f"cache_ttl_s must be a positive integer, got {cache_ttl_s}")

        self._url = url # URL of the JWKS endpoint
        self._timeout_s = int(timeout_s) # Timeout in seconds
        self._cache = _JwksCache(int(cache_ttl_s)) # Cache for JWKS keys
        self._breaker = breaker # Circuit breaker for JWKS fetch

    def get_key(self, kid: str) -> Optional[Any]:
        """Return the prepared key for the given KID if cached."""

        if not kid or not isinstance(kid, str):
            raise ValueError(f"kid must be a non-empty string, got {kid}")

        return self._cache._get(kid)

    def set_all(self, kid_to_key: Dict[str, Any]) -> None:
        """Atomically replace the cached keys with the provided mapping."""

        if not kid_to_key or not isinstance(kid_to_key, dict):
            raise ValueError(f"kid_to_key must be a non-empty dictionary, got {kid_to_key}")

        self._cache._set_all(kid_to_key)

    def age_seconds(self) -> float:
        """Return seconds since the last successful JWKS fetch (monotonic)."""

        return self._cache._age_seconds()

    def is_expired(self) -> bool:
        """Return True when the cache is empty or the TTL has elapsed."""

        return self._cache._is_expired()

    def invalidate(self) -> None:
        """Clear all cached keys and reset the age."""

        self._cache._clear()

    def fetch_raw(self) -> Dict[str, Any]:
        """Fetch the raw JWKS document from the endpoint."""

        if urlopen is None:
            raise ValueError("HTTP client unavailable for JWKS fetch")

        def _net_call():
            """Network call to fetch the JWKS document."""

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
        """Prepare the JWKS keys for use."""

        if not jwks or not isinstance(jwks, dict):
            raise ValueError("jwks must be a non-empty dictionary")

        kid_to_key: Dict[str, Any] = {}
        keys = jwks.get("keys")

        if not isinstance(keys, list):
            raise ValueError("JWKS keys must be a list")

        # Iterate over the keys and prepare them for use
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