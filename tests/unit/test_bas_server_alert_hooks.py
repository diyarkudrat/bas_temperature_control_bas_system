from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest


def test_add_event_hook_and_trigger_invokes_callbacks(monkeypatch):
    # Import module under test
    import server.bas_server as appmod

    called = {"n": 0, "payload": None}

    def cb(payload):
        called["n"] += 1
        called["payload"] = payload

    appmod.add_event_hook("sensor_fault", cb)
    appmod._trigger_event("sensor_fault", {"x": 1})

    assert called["n"] >= 1 and called["payload"] == {"x": 1}


def test_trigger_alert_sends_sms_when_targets_present(monkeypatch):
    import server.bas_server as appmod

    sent = {"n": 0, "to": []}

    def fake_send_sms(to_number: str, body: str, **kw):
        sent["n"] += 1
        sent["to"].append(to_number)
        return SimpleNamespace(message_sid="SMx")

    monkeypatch.setattr(appmod.alert_service, "send_sms", fake_send_sms)

    # Use a Flask app context to allow access to 'g'
    with appmod.app.app_context():
        ok = appmod._trigger_alert("msg", severity="error", sms_to=["+1", "+2"], email_to=["a@test"])  # email path only logs
        assert ok is True
    assert sent["n"] == 2 and sent["to"] == ["+1", "+2"]


def test_trigger_alert_handles_exception_and_returns_false(monkeypatch):
    import server.bas_server as appmod

    def boom(*a, **k):
        raise RuntimeError("fail")

    monkeypatch.setattr(appmod.alert_service, "send_sms", boom)
    # sms_to triggers send, which will raise and be caught
    ok = appmod._trigger_alert("m", severity="error", sms_to=["+1"]) 
    assert ok is False


