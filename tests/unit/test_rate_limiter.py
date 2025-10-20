from __future__ import annotations

import time

from server.services.rate_limiter import AlertRateLimiter, AlertRateLimitConfig


def test_burst_and_rate_allow():
    cfg = AlertRateLimitConfig(tokens_per_minute=60, burst_capacity=2, global_sms_per_minute=100, global_email_per_minute=100)
    rl = AlertRateLimiter(cfg)
    # First two allowed, third denied due to burst
    assert rl.allow("k", "sms")[0] is True
    assert rl.allow("k", "sms")[0] is True
    allowed, reason = rl.allow("k", "sms")
    assert allowed is False and reason == "burst_exceeded"


def test_global_cap_and_window_rotation(monkeypatch):
    # Small global caps
    cfg = AlertRateLimitConfig(tokens_per_minute=100, burst_capacity=100, global_sms_per_minute=2, global_email_per_minute=1)
    rl = AlertRateLimiter(cfg)

    # Consume SMS global cap
    assert rl.allow("a", "sms")[0] is True
    assert rl.allow("b", "sms")[0] is True
    allowed, reason = rl.allow("c", "sms")
    assert allowed is False and reason == "global_minute_cap_exceeded"

    # Rotate window by faking time
    base = time.time()
    monkeypatch.setattr("time.time", lambda: base + 61)
    # After rotation, allowed again
    assert rl.allow("c", "sms")[0] is True


