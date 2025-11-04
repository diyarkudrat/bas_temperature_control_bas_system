"""Unit tests for healthcheck helpers."""

from __future__ import annotations

import pytest

from tests.utils.healthcheck import failing_probe, healthy_probe


def test_failing_probe_exhausts_failures_then_recovers():
    probe = failing_probe(failure_count=2)

    with pytest.raises(RuntimeError):
        probe()
    with pytest.raises(RuntimeError):
        probe()

    probe()
    assert probe.calls == 3


def test_healthy_probe_never_raises():
    probe = healthy_probe()
    for _ in range(3):
        probe()

    assert probe.calls == 3

