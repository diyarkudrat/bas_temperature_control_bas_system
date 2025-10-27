import types

import importlib
import builtins


def test_batching_and_snapshot(monkeypatch):
    metrics_mod = importlib.import_module('server.auth.metrics')
    m = metrics_mod.MetricsRecorder()

    # Below flush threshold; snapshot should still reflect increments due to forced flush
    for _ in range(10):
        m.inc_jwt_attempt()
    for _ in range(3):
        m.inc_jwt_failure()
    for _ in range(5):
        m.inc_session_attempt()

    snap = m.snapshot()
    assert snap["jwt_attempts"] == 10
    assert snap["jwt_failures"] == 3
    assert snap["session_attempts"] == 5


def test_observe_success_and_flush(monkeypatch):
    metrics_mod = importlib.import_module('server.auth.metrics')
    m = metrics_mod.MetricsRecorder()

    m.observe_jwt_success(4.0)
    m.observe_jwt_success(6.0)
    m.observe_session_success(2.5)
    # Force flush
    m.flush()
    snap = m.snapshot()
    assert snap["jwt_success"] == 2
    assert abs(snap["jwt_latency_ms_sum"] - 10.0) < 1e-6
    assert snap["session_success"] == 1
    assert abs(snap["session_latency_ms_sum"] - 2.5) < 1e-6


def test_sampling_bounds_with_time_mock(monkeypatch):
    metrics_mod = importlib.import_module('server.auth.metrics')

    # Control time to trigger sampler adjustment without sleeping
    now_ms = [1_000_000_000_000]

    class FakeTime:
        @staticmethod
        def time():
            return now_ms[0] / 1000.0

    # Patch the module's time reference
    monkeypatch.setattr(metrics_mod, 'time', FakeTime)

    m = metrics_mod.MetricsRecorder()

    # Drive volume window
    for _ in range(50):
        m.inc_jwt_attempt()

    # Advance >2s to force adjustment
    now_ms[0] += 2500
    # Next call should evaluate sampler and potentially adjust rate
    m.inc_session_attempt()

    # Sample rate must remain within [0.01, 0.1]
    assert 0.01 <= m._sample_rate <= 0.1


def test_no_module_level_globals_created():
    metrics_mod = importlib.import_module('server.auth.metrics')
    # Ensure no obvious instance singletons are created at import time
    # We allow class names, but not lowercase instance-like objects
    disallowed_names = [
        name for name in dir(metrics_mod)
        if not name.startswith('__') and name[0].islower()
    ]
    # The module should not expose an instance such as 'auth_metrics' or similar
    assert 'auth_metrics' not in disallowed_names


