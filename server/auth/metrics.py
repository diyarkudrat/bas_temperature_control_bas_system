"""
Authentication metrics utilities.

Provides a low-overhead, thread-safe metrics recorder with batched counters,
coarse histograms, and dynamic sampling. The recorder is dependency-injection
friendly and contains no module-level global state. A backwards-compatible
`AuthMetrics` alias is provided for existing call sites.
"""

from __future__ import annotations

import threading
import time


class MetricsRecorder:
    """Low-overhead, DI-friendly metrics recorder.

    - Thread-safe counters with micro-batching to reduce contention
    - Latency histograms with dynamic sampling
    - No module-level globals; safe to inject per app or per request
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Totals (materialized on flush)
        self.jwt_attempts = 0
        self.jwt_failures = 0
        self.session_attempts = 0
        self.session_failures = 0
        self.jwt_latency_ms_sum = 0.0
        self.jwt_success = 0
        self.session_latency_ms_sum = 0.0
        self.session_success = 0

        # Batch buffers (merged on flush or snapshot)
        self._batch_counts = {
            "jwt_attempts": 0,
            "jwt_failures": 0,
            "session_attempts": 0,
            "session_failures": 0,
            "jwt_success": 0,
            "session_success": 0,
        }
        self._batch_sums = {
            "jwt_latency_ms_sum": 0.0,
            "session_latency_ms_sum": 0.0,
        }
        self._last_flush_ms = int(time.time() * 1000)
        self._flush_interval_ms = 1000  # opportunistic flush period
        self._batch_flush_threshold = 64  # combined incrs before flush
        self._batch_size = 0

        # Dynamic sampling (1% .. 10%) based on recent volume
        self._sample_rate = 0.01
        self._last_adjust_ms = int(time.time() * 1000)
        self._volume_window = []  # list[(ms, 1)]
        self._max_window = 256

        # Histograms: fixed buckets in ms
        self._jwt_hist = [0, 0, 0, 0, 0, 0]  # <1, <5, <20, <50, <200, >=200
        self._sess_hist = [0, 0, 0, 0, 0, 0]

        self.revocations = 0
        self.rate_limits_hit = 0
        self.breaker_opens = 0
        self._limit_checks_ms_hist = [0, 0, 0, 0, 0, 0]  # <0.5, <1, <2, <5, <10, >=10
        self._breaker_backoff_s_hist = [0, 0, 0, 0, 0]   # <0.1, <0.5, <1, <5, >=5

        # Simple spike alerting (counts within window)
        self._evt_window = []  # list[(ms, kind)] kind in {"rev","rl","bo"}
        self._evt_max = 256

    # ------------------------- batching -------------------------
    def _flush_locked(self) -> None:
        """Merge batch buffers into totals. Caller must hold lock."""
        if self._batch_size == 0:
            return

        self.jwt_attempts += self._batch_counts["jwt_attempts"]
        self.jwt_failures += self._batch_counts["jwt_failures"]
        self.session_attempts += self._batch_counts["session_attempts"]
        self.session_failures += self._batch_counts["session_failures"]
        self.jwt_success += self._batch_counts["jwt_success"]
        self.session_success += self._batch_counts["session_success"]
        self.jwt_latency_ms_sum += float(self._batch_sums["jwt_latency_ms_sum"]) 
        self.session_latency_ms_sum += float(self._batch_sums["session_latency_ms_sum"]) 
        
        # reset
        for k in self._batch_counts:
            self._batch_counts[k] = 0
        for k in self._batch_sums:
            self._batch_sums[k] = 0.0
        self._batch_size = 0
        self._last_flush_ms = int(time.time() * 1000)

    def _maybe_flush_locked(self) -> None:
        now_ms = int(time.time() * 1000)
        if (
            self._batch_size >= self._batch_flush_threshold
            or (now_ms - self._last_flush_ms) >= self._flush_interval_ms
        ):
            self._flush_locked()

    def _should_sample(self) -> bool:
        # Simple time+volume-based sampler; constant-time on average
        now_ms = int(time.time() * 1000)
        with self._lock:
            # Use totals + batched to estimate activity fairly
            self._volume_window.append((now_ms, 1))
            if len(self._volume_window) > self._max_window:
                self._volume_window.pop(0)
            # Adjust at most every 2s
            if now_ms - self._last_adjust_ms >= 2000:
                self._last_adjust_ms = now_ms
                if self._volume_window:
                    span_ms = max(1, self._volume_window[-1][0] - self._volume_window[0][0])
                    rate = (len(self._volume_window) / (span_ms / 1000.0)) if span_ms > 0 else 0.0
                else:
                    rate = 0.0
                # Map rate to sample 1%..10% (higher volume -> lower sample)
                if rate <= 10:
                    self._sample_rate = 0.1
                elif rate <= 50:
                    self._sample_rate = 0.05
                elif rate <= 200:
                    self._sample_rate = 0.02
                else:
                    self._sample_rate = 0.01
            # Deterministic hashless sampling over (totals + batch)
            total = (
                self.jwt_attempts
                + self.session_attempts
                + self._batch_counts["jwt_attempts"]
                + self._batch_counts["session_attempts"]
                + 1
            )
            stride = max(1, int(1.0 / self._sample_rate))
            return (total % stride) == 0

    def _bucket_idx(self, ms: float) -> int:
        if ms < 1.0:
            return 0
        if ms < 5.0:
            return 1
        if ms < 20.0:
            return 2
        if ms < 50.0:
            return 3
        if ms < 200.0:
            return 4
        return 5

    def _bucket_idx_limit_ms(self, ms: float) -> int:
        if ms < 0.5:
            return 0
        if ms < 1.0:
            return 1
        if ms < 2.0:
            return 2
        if ms < 5.0:
            return 3
        if ms < 10.0:
            return 4
        return 5

    def _bucket_idx_backoff_s(self, s: float) -> int:
        if s < 0.1:
            return 0
        if s < 0.5:
            return 1
        if s < 1.0:
            return 2
        if s < 5.0:
            return 3
        return 4

    def _record_evt(self, kind: str) -> None:
        now_ms = int(time.time() * 1000)
        with self._lock:
            self._evt_window.append((now_ms, kind))
            if len(self._evt_window) > self._evt_max:
                self._evt_window.pop(0)

    def inc_jwt_attempt(self) -> None:
        with self._lock:
            self._batch_counts["jwt_attempts"] += 1
            self._batch_size += 1
            self._maybe_flush_locked()

    def inc_jwt_failure(self) -> None:
        with self._lock:
            self._batch_counts["jwt_failures"] += 1
            self._batch_size += 1
            self._maybe_flush_locked()

    def observe_jwt_success(self, latency_ms: float) -> None:
        sample = self._should_sample()
        with self._lock:
            self._batch_counts["jwt_success"] += 1
            self._batch_sums["jwt_latency_ms_sum"] += float(latency_ms)
            self._batch_size += 1
            if sample:
                self._jwt_hist[self._bucket_idx(float(latency_ms))] += 1
            self._maybe_flush_locked()

    def inc_session_attempt(self) -> None:
        with self._lock:
            self._batch_counts["session_attempts"] += 1
            self._batch_size += 1
            self._maybe_flush_locked()

    def inc_session_failure(self) -> None:
        with self._lock:
            self._batch_counts["session_failures"] += 1
            self._batch_size += 1
            self._maybe_flush_locked()

    def observe_session_success(self, latency_ms: float) -> None:
        sample = self._should_sample()
        with self._lock:
            self._batch_counts["session_success"] += 1
            self._batch_sums["session_latency_ms_sum"] += float(latency_ms)
            self._batch_size += 1
            if sample:
                self._sess_hist[self._bucket_idx(float(latency_ms))] += 1
            self._maybe_flush_locked()

    # -------- Phase 4 counters/histograms --------
    def inc_revocation(self) -> None:
        with self._lock:
            self.revocations += 1
            self._record_evt("rev")

    def inc_rate_limited(self) -> None:
        with self._lock:
            self.rate_limits_hit += 1
            self._record_evt("rl")

    def inc_breaker_open(self) -> None:
        with self._lock:
            self.breaker_opens += 1
            self._record_evt("bo")

    def observe_limit_check_ms(self, ms: float) -> None:
        with self._lock:
            self._limit_checks_ms_hist[self._bucket_idx_limit_ms(float(ms))] += 1

    def observe_breaker_backoff_s(self, s: float) -> None:
        with self._lock:
            self._breaker_backoff_s_hist[self._bucket_idx_backoff_s(float(s))] += 1

    def snapshot(self) -> dict:
        """Return a consistent snapshot of metrics counts and sums."""
        with self._lock:
            # Ensure batch buffers are merged before reading
            self._flush_locked()
            return {
                "jwt_attempts": self.jwt_attempts,
                "jwt_failures": self.jwt_failures,
                "jwt_success": self.jwt_success,
                "jwt_latency_ms_sum": self.jwt_latency_ms_sum,
                "session_attempts": self.session_attempts,
                "session_failures": self.session_failures,
                "session_success": self.session_success,
                "session_latency_ms_sum": self.session_latency_ms_sum,
                "sample_rate": round(self._sample_rate, 3),
                "jwt_hist": list(self._jwt_hist),
                "session_hist": list(self._sess_hist),
                "revocations": self.revocations,
                "rate_limits_hit": self.rate_limits_hit,
                "breaker_opens": self.breaker_opens,
                "limit_checks_ms_hist": list(self._limit_checks_ms_hist),
                "breaker_backoff_s_hist": list(self._breaker_backoff_s_hist),
            }

    def flush(self) -> None:
        """Force a batch flush to totals."""
        with self._lock:
            self._flush_locked()


# Backwards compatibility: preserve existing import/type name
class AuthMetrics(MetricsRecorder):
    pass


