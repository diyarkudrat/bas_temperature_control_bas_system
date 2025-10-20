from __future__ import annotations

import pytest

from server.models.alert import Alert, AlertSeverity


def test_alert_severity_from_string_and_errors():
    assert AlertSeverity.from_string("INFO") is AlertSeverity.INFO
    assert AlertSeverity.from_string("critical") is AlertSeverity.CRITICAL
    with pytest.raises(ValueError):
        AlertSeverity.from_string("bad")


def test_alert_validation_and_serialization():
    a = Alert(
        message="m",
        severity=AlertSeverity.ERROR,
        sms_to=["+1"],
        email_to=["a@test"],
        subject="sub",
        tenant_id="t",
        device_id="d",
        event_type="E",
        metadata={"k": "v"},
    )
    d = a.to_dict()
    assert d["message"] == "m"
    assert d["severity"] == "error"
    assert d["sms_to"] == ["+1"]
    assert d["email_to"] == ["a@test"]
    assert d["subject"] == "sub"
    assert d["tenant_id"] == "t"
    assert d["device_id"] == "d"
    assert d["event_type"] == "E"
    assert d["metadata"]["k"] == "v"

    # Roundtrip
    a2 = Alert.from_dict(d)
    assert a2.message == a.message and a2.severity == a.severity


def test_alert_invalid_inputs():
    with pytest.raises(ValueError):
        Alert(message="", severity=AlertSeverity.INFO)
    with pytest.raises(ValueError):
        # long message
        Alert(message="x" * 3000, severity=AlertSeverity.INFO)
    with pytest.raises(ValueError):
        # invalid severity type
        Alert(message="m", severity="bad")  # type: ignore[arg-type]


