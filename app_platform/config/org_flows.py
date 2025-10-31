"""Configuration surface for organization onboarding flows."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
        if minimum is not None and parsed < minimum:
            return minimum
        return parsed
    except ValueError:
        return default


def _float_env(name: str, default: float, *, minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = float(raw)
    except ValueError:
        return default
    if minimum is not None and parsed < minimum:
        parsed = minimum
    if maximum is not None and parsed > maximum:
        parsed = maximum
    return parsed


@dataclass(slots=True)
class OrgFlowsConfig:
    """Normalized configuration for org signup, invites, and devices."""

    org_signup_v2_enabled: bool = False
    device_rbac_enforcement: bool = False
    provisioning_key_id: str | None = None
    provisioning_private_key_secret: str | None = None
    provisioning_jwt_ttl_seconds: int = 60
    invite_quota_per_tenant: int = 20
    invite_quota_window_minutes: int = 60
    invite_ttl_hours: int = 72
    captcha_provider: str | None = None
    captcha_site_key: str | None = None
    captcha_secret_handle: str | None = None
    captcha_min_score: float = 0.5
    default_device_quota: int = 100
    idempotency_ttl_hours: int = 24
    replay_cache_ttl_seconds: int = 120
    secret_manager_project: str | None = None
    device_credential_rotation_hours: int = 24 * 30

    @classmethod
    def from_env(cls) -> "OrgFlowsConfig":
        return cls(
            org_signup_v2_enabled=_bool_env("ORG_SIGNUP_V2", False),
            device_rbac_enforcement=_bool_env("DEVICE_RBAC_ENFORCEMENT", False),
            provisioning_key_id=os.getenv("ORG_SIGNUP_SIGNING_KEY_ID"),
            provisioning_private_key_secret=os.getenv("ORG_SIGNUP_PRIVATE_KEY_SECRET"),
            provisioning_jwt_ttl_seconds=_int_env("ORG_SIGNUP_JWT_TTL_SECONDS", 60, minimum=30),
            invite_quota_per_tenant=_int_env("INVITE_MAX_PER_TENANT", 20, minimum=1),
            invite_quota_window_minutes=_int_env("INVITE_QUOTA_WINDOW_MINUTES", 60, minimum=15),
            invite_ttl_hours=_int_env("INVITE_TTL_HOURS", 72, minimum=1),
            captcha_provider=os.getenv("CAPTCHA_PROVIDER"),
            captcha_site_key=os.getenv("CAPTCHA_SITE_KEY"),
            captcha_secret_handle=os.getenv("CAPTCHA_SECRET_HANDLE"),
            captcha_min_score=_float_env("CAPTCHA_MIN_SCORE", 0.5, minimum=0.0, maximum=1.0),
            default_device_quota=_int_env("DEFAULT_DEVICE_QUOTA", 100, minimum=1),
            idempotency_ttl_hours=_int_env("IDEMPOTENCY_TTL_HOURS", 24, minimum=1),
            replay_cache_ttl_seconds=_int_env("REQUEST_JWT_REPLAY_TTL_SECONDS", 120, minimum=30),
            secret_manager_project=os.getenv("ORG_SECRET_PROJECT"),
            device_credential_rotation_hours=_int_env("DEVICE_CREDENTIAL_ROTATION_HOURS", 24 * 30, minimum=1),
        )


__all__ = ["OrgFlowsConfig"]


