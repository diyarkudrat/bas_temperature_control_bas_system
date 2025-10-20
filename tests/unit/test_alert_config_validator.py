from __future__ import annotations

import pytest

from server.services.validators.alert_config_validator import validate_alert_config


def test_valid_minimal_sms_config():
    cfg = {
        "version": "1.2.3",
        "providers": {
            "twilio": {
                "account_sid": "ACxxx",
                "auth_token": "tok",
                "from_number": "+15550001",
            }
        },
        "routing": {
            "default_channels": ["sms", "sms"],  # duplicate to test normalization
            "severity_routes": {"error": ["sms"]},
        },
    }
    res = validate_alert_config(cfg)
    assert res.success is True
    assert res.errors == []
    assert res.normalized is not None
    # Duplicates normalized to unique
    assert res.normalized["routing"]["default_channels"] == ["sms"]


def test_missing_providers_when_channels_referenced():
    cfg = {
        "version": "1.0.0",
        "providers": {
            # Neither twilio nor email are valid for referenced channels
        },
        "routing": {
            "default_channels": ["sms", "email"],
        },
    }
    res = validate_alert_config(cfg)
    assert res.success is False
    # Both sms and email should complain
    joined = "\n".join(res.errors)
    assert "providers.twilio: required" in joined
    assert "providers.email: required" in joined


def test_semver_tenants_and_email_validation():
    cfg = {
        "version": "1",  # bad
        "providers": {
            "twilio": {
                "account_sid": "ACxxx",
                "auth_token": "tok",
                "from_number": "+15550001",
            }
        },
        "routing": {
            "default_channels": ["sms"],
            "tenants": {
                "t1": {
                    "channels": ["sms", "push"],  # invalid channel
                    "email_to": ["bad"]  # invalid email
                }
            }
        },
        "limits": {"max_sms_per_minute": -1, "burst": 0},
    }
    res = validate_alert_config(cfg)
    assert res.success is False
    joined = "\n".join(res.errors)
    assert "version:" in joined
    assert "invalid channels" in joined
    assert "invalid emails" in joined
    assert "limits.max_sms_per_minute" in joined
    assert "limits.burst" in joined


def test_schema_error_is_included(monkeypatch):
    # Force schema errors without requiring jsonschema package: patch at the import site
    monkeypatch.setattr("server.services.validators.alert_config_validator.run_jsonschema_validation", lambda config, schema: ["schema: boom"])    

    cfg = {
        "version": "1.0.0",
        "providers": {},
        "routing": {"default_channels": ["sms"]},
    }
    res = validate_alert_config(cfg, schema={"type": "object"})
    assert res.success is False
    assert any("schema:" in e for e in res.errors)


def test_email_defaults_use_tls_default_true():
    cfg = {
        "version": "1.0.0",
        "providers": {
            "twilio": {
                "account_sid": "ACxxx",
                "auth_token": "tok",
                "from_number": "+15550001",
            },
            "email": {
                "smtp_host": "smtp.test",
                "smtp_port": 587,
                # no use_tls
            },
        },
        "routing": {"default_channels": ["sms", "email"]},
    }
    res = validate_alert_config(cfg)
    assert res.success is True
    assert res.normalized["providers"]["email"]["use_tls"] is True


