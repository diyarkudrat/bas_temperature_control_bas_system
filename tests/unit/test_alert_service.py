from __future__ import annotations

import types
import pytest
from unittest.mock import Mock, patch


# Import target module
from server.services.alerting import AlertService, EmailConfig, AlertingNotInitializedError, AlertingSendError


class DummySMTP:
    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logged_in = False
        self.started_tls = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, username, password):
        self.logged_in = True

    def send_message(self, msg):
        # Accept any EmailMessage
        return {}


class DummySMTPSsl(DummySMTP):
    def __init__(self, host, port, context=None, timeout=None):
        super().__init__(host, port, timeout=timeout)


def test_send_email_tls_branch(monkeypatch):
    svc = AlertService()

    monkeypatch.setattr("smtplib.SMTP", DummySMTP)
    monkeypatch.setattr("smtplib.SMTP_SSL", DummySMTPSsl)

    cfg = EmailConfig(smtp_host="smtp.test", smtp_port=587, username="u", password="p", use_tls=True, from_email="noreply@test")
    msg_id = svc.send_email(to_addresses=["dest@test"], subject="Hello", body_text=" body ", email_config=cfg)
    assert isinstance(msg_id, str)


def test_send_email_ssl_branch(monkeypatch):
    svc = AlertService()

    monkeypatch.setattr("smtplib.SMTP", DummySMTP)
    monkeypatch.setattr("smtplib.SMTP_SSL", DummySMTPSsl)

    cfg = EmailConfig(smtp_host="smtp.test", smtp_port=465, username=None, password=None, use_tls=False, from_email=None)
    msg_id = svc.send_email(to_addresses="a@test", subject="S", body_text="text", email_config=cfg)
    assert isinstance(msg_id, str)


def test_send_email_errors(monkeypatch):
    svc = AlertService()
    with pytest.raises(ValueError):
        svc.send_email(to_addresses=[], subject="s", body_text="x", email_config=EmailConfig(smtp_host="h"))
    with pytest.raises(ValueError):
        svc.send_email(to_addresses=["a@test"], subject="s", body_text=None, body_html=None, email_config=EmailConfig(smtp_host="h"))
    with pytest.raises(AlertingNotInitializedError):
        svc.send_email(to_addresses=["a@test"], subject="s", body_text="x", email_config=None)

    cfg_bad = EmailConfig(smtp_host="", smtp_port=0)
    with pytest.raises(AlertingNotInitializedError):
        svc.send_email(to_addresses=["a@test"], subject="s", body_text="x", email_config=cfg_bad)

    # Simulate SMTP failure raising
    class FailingSMTP(DummySMTP):
        def send_message(self, msg):  # type: ignore[override]
            raise RuntimeError("fail")

    monkeypatch.setattr("smtplib.SMTP", FailingSMTP)
    with pytest.raises(AlertingSendError):
        svc.send_email(to_addresses=["a@test"], subject="s", body_text="x", email_config=EmailConfig(smtp_host="smtp", smtp_port=587))


def test_send_sms_success(monkeypatch):
    svc = AlertService()

    class DummyTwilioMessages:
        def create(self, **params):
            class M:
                sid = "SM123"
            # Ensure body was minimized (collapsed spaces)
            if "body" in params:
                assert "  " not in params["body"]
            return M()

    class DummyTwilioClient:
        messages = DummyTwilioMessages()

    # Patch Twilio helpers in alerting module namespace
    monkeypatch.setattr("server.services.alerting.get_twilio_client", lambda auto_init_from_env=True: DummyTwilioClient())
    monkeypatch.setattr("server.services.alerting.get_twilio_sender_params", lambda: {"from_": "+15550001"})

    res = svc.send_sms(to_number="+15551234567", body="hello   world")
    assert res.provider == "twilio"
    assert res.message_sid == "SM123"


def test_send_sms_media_and_error(monkeypatch):
    svc = AlertService()

    # No client initialized
    monkeypatch.setattr("server.services.alerting.get_twilio_client", lambda auto_init_from_env=True: None)
    with pytest.raises(AlertingNotInitializedError):
        svc.send_sms(to_number="+1", body="", media_urls=["http://i"])

    class ErrClient:
        class messages:  # type: ignore
            @staticmethod
            def create(**params):
                raise RuntimeError("boom")

    monkeypatch.setattr("server.services.alerting.get_twilio_client", lambda auto_init_from_env=True: ErrClient())
    monkeypatch.setattr("server.services.alerting.get_twilio_sender_params", lambda: {"messaging_service_sid": "MGxxx"})
    with pytest.raises(AlertingSendError):
        svc.send_sms(to_number="+1555", body="x")


def test_send_with_fallback_paths(monkeypatch):
    svc = AlertService()

    # Email first succeeds
    monkeypatch.setattr("server.services.alerting.AlertService.send_email", lambda self, **kw: "mid123")
    res = svc.send_with_fallback(email_first=True, email_params={"to_addresses": "a@b", "subject": "s", "body_text": "t", "email_config": EmailConfig(smtp_host="h")})
    assert res["email"]["ok"] is True

    # Email fails, SMS fallback
    def _raise(*args, **kwargs):
        raise RuntimeError("x")

    monkeypatch.setattr("server.services.alerting.AlertService.send_email", lambda *a, **k: _raise())
    monkeypatch.setattr("server.services.alerting.AlertService.send_sms", lambda self, **kw: types.SimpleNamespace(message_sid="SM1"))
    res2 = svc.send_with_fallback(email_first=True, email_params={}, sms_params={"to_number": "+1", "body": "x"})
    assert res2["email"]["ok"] is False and res2["sms"]["ok"] is True

    # SMS first succeeds
    monkeypatch.setattr("server.services.alerting.AlertService.send_sms", lambda self, **kw: types.SimpleNamespace(message_sid="SM2"))
    res3 = svc.send_with_fallback(email_first=False, sms_params={"to_number": "+1", "body": "x"})
    assert res3["sms"]["ok"] is True

    # SMS fails then email fallback works
    monkeypatch.setattr("server.services.alerting.AlertService.send_sms", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sboom")))
    monkeypatch.setattr("server.services.alerting.AlertService.send_email", lambda self, **kw: "mid456")
    res4 = svc.send_with_fallback(email_first=False, email_params={"to_addresses": "a@b", "subject": "s", "body_text": "t", "email_config": EmailConfig(smtp_host="h")}, sms_params={"to_number": "+1", "body": "x"})
    assert res4["sms"]["ok"] is False and res4["email"]["ok"] is True


def test_helpers_minimize_and_secure_link():
    svc = AlertService()
    text = " a  b\n c\t d "
    assert svc.minimize_content(text) == "a b c d"
    long = "x" * 1000
    assert len(svc.minimize_content(long, max_len=10)) == 10
    url = svc.secure_link_generator("https://example.com/x", {"a": "b c"})
    assert url.startswith("https://example.com/x?")
    # urllib may encode space as '+' for query params; accept both
    assert ("%20" in url) or ("+" in url)


