"""Twilio client singleton factory for distributed backend usage."""

from __future__ import annotations

import os
import logging
import threading
from dataclasses import dataclass
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TwilioConfig:
    """Configuration for Twilio client and default sender."""
    account_sid: str
    auth_token: str
    from_number: Optional[str] = None  # E.164 phone, e.g. +15551234567
    messaging_service_sid: Optional[str] = None  # Preferred for SMS at scale

    @classmethod
    def from_env(cls) -> "TwilioConfig":
        """Build TwilioConfig from environment variables."""
        return cls(
            account_sid=os.getenv("TWILIO_ACCOUNT_SID", ""),
            auth_token=os.getenv("TWILIO_AUTH_TOKEN", ""),
            from_number=os.getenv("TWILIO_FROM_NUMBER"),
            messaging_service_sid=os.getenv("TWILIO_MESSAGING_SERVICE_SID"),
        )


_twilio_client: Optional[Any] = None
_twilio_config: Optional[TwilioConfig] = None
_init_lock = threading.Lock()


def _validate_config(config: TwilioConfig) -> None:
    """Validate that required config fields are present."""
    if not config.account_sid or not config.auth_token:
        raise TwilioNotConfiguredError("Twilio account_sid and auth_token are required")


def create_twilio_client(config: TwilioConfig) -> Any:
    """
    Create a Twilio REST client from config.
    Import is local to avoid hard dependency at module import time.
    """
    _validate_config(config)
    try:
        from twilio.rest import Client  # type: ignore
    except Exception as exc:
        raise TwilioNotConfiguredError(
            "Failed to import Twilio SDK. Ensure 'twilio' is installed."
        ) from exc

    try:
        client = Client(config.account_sid, config.auth_token)
        return client
    except Exception as exc:
        logger.error("Failed to construct Twilio client: %s", exc)
        raise


def init_twilio_global(config: Optional[TwilioConfig] = None) -> Any:
    """
    Idempotently initialize the global Twilio client.
    Safe for concurrent calls in a distributed, multi-worker environment.
    """
    global _twilio_client, _twilio_config
    if _twilio_client is not None:
        return _twilio_client

    with _init_lock:
        if _twilio_client is not None:
            return _twilio_client

        cfg = config or TwilioConfig.from_env()
        client = create_twilio_client(cfg)
        _twilio_client = client
        _twilio_config = cfg
        logger.info("Twilio client initialized")
        return _twilio_client


def get_twilio_client(auto_init_from_env: bool = True) -> Optional[Any]:
    """
    Get the global Twilio client, optionally auto-initializing from environment.
    Returns None if not initialized and auto_init_from_env is False or fails.
    """
    if _twilio_client is not None:
        return _twilio_client

    if not auto_init_from_env:
        return None

    try:
        return init_twilio_global()
    except Exception as exc:
        logger.warning("Twilio auto-init failed: %s", exc)
        return None


def get_twilio_sender_params() -> Dict[str, str]:
    """
    Return sender parameters to be merged into messages.create(...).
    Prefers Messaging Service SID when configured; falls back to from_ number.
    """
    if _twilio_config and _twilio_config.messaging_service_sid:
        return {"messaging_service_sid": _twilio_config.messaging_service_sid}
    if _twilio_config and _twilio_config.from_number:
        return {"from_": _twilio_config.from_number}
    return {}


def is_initialized() -> bool:
    """True if the global Twilio client has been initialized."""
    return _twilio_client is not None


def health_check() -> Dict[str, Any]:
    """
    Lightweight health status for Twilio client.
    Avoids network calls; focuses on local initialization state.
    """
    if not is_initialized():
        return {"status": "uninitialized"}
    try:
        params = get_twilio_sender_params()
        return {"status": "initialized", "sender_params": bool(params)}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def reset_twilio_client_for_tests() -> None:
    """
    Reset global client/config for tests. Do not use in production code paths.
    """
    global _twilio_client, _twilio_config
    with _init_lock:
        _twilio_client = None
        _twilio_config = None
        logger.info("Twilio client reset (tests)")


class TwilioNotConfiguredError(RuntimeError):
    """Raised when Twilio configuration is missing or invalid."""