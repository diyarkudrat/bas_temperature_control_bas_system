from server.config.rate_limit import RateLimitConfig, AtomicRateLimitConfig


def test_clamps_and_minima():
    cfg = RateLimitConfig(requests_per_second=-5, burst_capacity=0).clamped()
    assert cfg.requests_per_second >= cfg.min_rps
    assert cfg.burst_capacity >= cfg.min_burst

    cfg2 = RateLimitConfig(requests_per_second=1e9, burst_capacity=1_000_000_000).clamped()
    assert cfg2.requests_per_second <= cfg2.max_rps
    assert cfg2.burst_capacity <= cfg2.max_burst


def test_atomic_hot_reload_swap_and_versioning():
    holder = AtomicRateLimitConfig(RateLimitConfig(requests_per_second=10, burst_capacity=50))
    snap1 = holder.get_snapshot()
    v1 = holder.version()

    # Swap to a different config
    new_cfg = RateLimitConfig(requests_per_second=200, burst_capacity=500)
    snap2 = holder.swap(new_cfg)
    v2 = holder.version()

    assert snap2.requests_per_second == 200
    assert snap2.burst_capacity == 500
    assert v2 == v1 + 1

    # Update with parsing errors is ignored for those fields
    snap3 = holder.update(requests_per_second="bad", burst_capacity="nope")
    assert snap3.requests_per_second == 200
    assert snap3.burst_capacity == 500


def test_atomic_update_with_per_user_limits_and_clamp():
    holder = AtomicRateLimitConfig(RateLimitConfig(requests_per_second=5, burst_capacity=5))
    snap = holder.update(
        requests_per_second=0.1,  # will clamp to min
        burst_capacity=0,         # will clamp to min
        per_user_limits={
            "/api/x": {"window_s": 60, "max_req": 10}
        }
    )
    assert snap.requests_per_second >= snap.min_rps
    assert snap.burst_capacity >= snap.min_burst
    assert "/api/x" in snap.per_user_limits


