"""Alerting service with Twilio SMS/MMS support."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from .twilio_client import (
    get_twilio_client,
    init_twilio_global,
    get_twilio_sender_params,
    TwilioConfig,
    TwilioNotConfiguredError,
)

logger = logging.getLogger(__name__)

class AlertingNotInitializedError(RuntimeError):
    """Raised when Twilio is not initialized and send is attempted."""


class AlertingSendError(RuntimeError):
    """Raised when a provider reports a send failure or unexpected error occurs."""


@dataclass(frozen=True)
class SMSResult:
    """Result of an SMS/MMS send operation."""
    provider: str
    message_sid: str
    to_number: str


class AlertService:
    """
    Minimal alerting service with Twilio SMS support.
    - Twilio is initialized once per-process via twilio_client singleton.
    - This service delegates init and client retrieval to that module.
    """

    def init_twilio(self, config: Optional[TwilioConfig] = None) -> None:
        """
        Initialize the global Twilio client (idempotent).
        If config is None, environment variables will be used.
        """
        try:
            init_twilio_global(config)
            logger.info("AlertService: Twilio initialized")
        except TwilioNotConfiguredError as exc:
            logger.error("AlertService: Twilio configuration invalid: %s", exc)
            raise AlertingNotInitializedError(str(exc)) from exc
        except Exception as exc:
            logger.error("AlertService: Twilio initialization failed: %s", exc)
            raise AlertingNotInitializedError("Failed to initialize Twilio") from exc

    def send_sms(
        self,
        to_number: str,
        body: str,
        *,
        media_urls: Optional[List[str]] = None,
        timeout_seconds: float = 15.0,
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> SMSResult:
        """
        Send an SMS (or MMS if media_urls provided) using Twilio.
        Returns SMSResult with the provider message SID on success.
        """
        if not to_number:
            raise ValueError("to_number is required")
        if not body and not media_urls:
            raise ValueError("Either body or media_urls must be provided")

        client = get_twilio_client(auto_init_from_env=True)
        if client is None:
            raise AlertingNotInitializedError("Twilio is not initialized")

        try:
            # Construct arguments: prefer Messaging Service SID, fallback to from_ number
            sender_params = get_twilio_sender_params()
            params: Dict[str, Any] = {
                "to": to_number,
                **sender_params,
            }
            if body:
                params["body"] = body
            if media_urls:
                params["media_url"] = media_urls
            if extra_params:
                params.update(extra_params)

            # Note: Twilio SDK doesn't expose per-call timeout; use SDK defaults.
            message = client.messages.create(**params)  # type: ignore[attr-defined]
            sid = getattr(message, "sid", None)
            if not sid:
                raise AlertingSendError("Twilio did not return a message SID")

            logger.debug("AlertService: SMS sent to %s sid=%s", to_number, sid)
            return SMSResult(provider="twilio", message_sid=sid, to_number=to_number)

        except Exception as exc:
            logger.error("AlertService: send_sms failed for %s: %s", to_number, exc)
            raise AlertingSendError("Failed to send SMS via Twilio") from exc


