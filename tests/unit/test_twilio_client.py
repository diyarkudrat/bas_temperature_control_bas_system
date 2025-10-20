from __future__ import annotations

from types import SimpleNamespace

from server.services import twilio_client as tc


def test_reset_and_health_uninitialized():
    tc.reset_twilio_client_for_tests()
    h = tc.health_check()
    assert h["status"] == "uninitialized"
    assert tc.get_twilio_sender_params() == {}


def test_init_and_sender_params_with_fakes(monkeypatch):
    # Avoid importing real twilio, replace factory with dummy
    dummy = SimpleNamespace()

    monkeypatch.setattr(tc, "create_twilio_client", lambda cfg: dummy)
    tc.reset_twilio_client_for_tests()

    cfg = tc.TwilioConfig(account_sid="ACx", auth_token="tok", from_number="+1")
    client = tc.init_twilio_global(cfg)
    assert client is dummy
    assert tc.is_initialized() is True
    # sender params fallback to from_
    assert tc.get_twilio_sender_params() == {"from_": "+1"}

    # Reset and prefer messaging service
    tc.reset_twilio_client_for_tests()
    monkeypatch.setattr(tc, "create_twilio_client", lambda cfg: dummy)
    cfg2 = tc.TwilioConfig(account_sid="ACx", auth_token="tok", messaging_service_sid="MGx")
    tc.init_twilio_global(cfg2)
    assert tc.get_twilio_sender_params() == {"messaging_service_sid": "MGx"}
    h = tc.health_check()
    assert h["status"] == "initialized" and h["sender_params"] is True


