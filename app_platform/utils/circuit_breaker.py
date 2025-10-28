from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Tuple, Any, Type


class CircuitBreaker:
    """Circuit breaker with monotonic time, correlation buckets, and probe state.

    States: CLOSED -> OPEN -> HALF_OPEN -> CLOSED
    - failure_threshold: failures to OPEN within window_seconds
    - half_open_after_s: time to transition OPEN -> HALF_OPEN
    - backoff_fn: callable(attempt:int)->sleep_s used by callers for retries
    - correlation_key_fn: fn(exc)->str groups failures to avoid misattribution
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        window_seconds: int = 30,
        half_open_after_s: int = 15,
        backoff_fn: Optional[Callable[[int], float]] = None,
        correlation_key_fn: Optional[Callable[[BaseException], str]] = None,
        min_fails: int = 3,
    ) -> None:
        self._lock = threading.Lock()
        self._state = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
        self._failures: list[Tuple[float, str]] = []  # (ts_monotonic, key)
        self._opened_at: float = 0.0
        self._half_open_probe_inflight = False
        self._threshold = max(min_fails, int(failure_threshold))
        self._window_s = float(window_seconds)
        self._half_open_after = float(half_open_after_s)
        self._backoff = backoff_fn or (lambda n: min(1.0, 0.05 * (2 ** max(0, n - 1))))
        self._corr_fn = correlation_key_fn or (lambda exc: getattr(exc, "__class__", type("")) .__name__ if exc else "generic")

    # --------------- State helpers ---------------
    def _prune(self, now: float) -> None:
        cutoff = now - self._window_s
        self._failures = [p for p in self._failures if p[0] >= cutoff]

    def _trip_if_needed(self, now: float) -> None:
        self._prune(now)
        if len(self._failures) >= self._threshold:
            # Require correlation of at least min_fails/2 to avoid random spikes
            keys: dict[str, int] = {}
            for _, k in self._failures:
                keys[k] = keys.get(k, 0) + 1
            if keys and max(keys.values()) >= max(1, self._threshold // 2):
                self._state = "OPEN"
                self._opened_at = now

    def allow_call(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._state == "OPEN":
                if (now - self._opened_at) >= self._half_open_after:
                    if not self._half_open_probe_inflight:
                        self._state = "HALF_OPEN"
                        self._half_open_probe_inflight = True
                        return True
                return False
            return True

    def on_success(self) -> None:
        with self._lock:
            if self._state == "HALF_OPEN":
                self._state = "CLOSED"
                self._half_open_probe_inflight = False
                self._failures.clear()

    def on_failure(self, exc: Optional[BaseException] = None) -> None:
        now = time.monotonic()
        key = self._corr_fn(exc) if exc else "generic"
        with self._lock:
            self._failures.append((now, str(key)))
            self._trip_if_needed(now)
            if self._state == "HALF_OPEN":
                self._state = "OPEN"
                self._opened_at = now
                self._half_open_probe_inflight = False

    # --------------- Convenience wrapper ---------------
    def wrap_call(self, fn: Callable[[], Any], *, max_tries: int = 1) -> Any:
        attempt = 0
        last_exc: Optional[BaseException] = None
        while attempt < max_tries:
            attempt += 1
            if not self.allow_call():
                raise RuntimeError("breaker_open")
            try:
                result = fn()
                self.on_success()
                return result
            except BaseException as exc:  # noqa: BLE001
                last_exc = exc
                self.on_failure(exc)
                if attempt < max_tries:
                    time.sleep(self._backoff(attempt))
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("call_failed")

    # --------------- Introspection ---------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "state": self._state,
                "failures": len(self._failures),
                "window_s": self._window_s,
                "half_open_after_s": self._half_open_after,
            }


def with_breaker(
    breaker: CircuitBreaker,
    *,
    max_tries: int = 1,
    retry_on: tuple[Type[BaseException], ...] = (Exception,),
    retry_if: Optional[Callable[[BaseException], bool]] = None,
):
    """Decorator to run a function under a CircuitBreaker with retries.

    The breaker governs admission and backoff; only exceptions matching retry_on
    (and passing retry_if when provided) are retried up to max_tries.
    """

    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            attempt = 0
            last_exc: Optional[BaseException] = None
            while attempt < max_tries:
                attempt += 1
                if not breaker.allow_call():
                    raise RuntimeError("breaker_open")
                try:
                    result = func(*args, **kwargs)
                    breaker.on_success()
                    return result
                except retry_on as exc:  # type: ignore[misc]
                    if retry_if is not None and not retry_if(exc):
                        breaker.on_failure(exc)
                        raise
                    last_exc = exc
                    breaker.on_failure(exc)
                    if attempt < max_tries:
                        time.sleep(breaker._backoff(attempt))
                except BaseException as exc:  # noqa: BLE001
                    breaker.on_failure(exc)
                    raise
            assert last_exc is not None
            raise last_exc

        return _wrapped

    return _decorator


