from __future__ import annotations

import json

from bas_server import app


def test_auth_health_endpoint_returns_payload(monkeypatch):
    client = app.test_client()
    resp = client.get('/api/health/auth')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "status" in data
    assert "provider" in data
    assert "now_epoch_ms" in data


