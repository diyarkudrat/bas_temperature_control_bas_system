"""Alerting service with Twilio SMS/MMS support."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Sequence
import smtplib
import ssl
from email.message import EmailMessage

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
class EmailConfig:
    """SMTP configuration for sending emails."""
    smtp_host: str
    smtp_port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    from_email: Optional[str] = None


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

    # --- Email support ---
    def _build_email_message(
        self,
        subject: str,
        to_addresses: Sequence[str],
        body_text: Optional[str],
        body_html: Optional[str],
        from_email: Optional[str],
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["To"] = ", ".join(to_addresses)
        if from_email:
            msg["From"] = from_email
        # Prefer multipart alternative when HTML present
        if body_html:
            msg.set_content(body_text or "")
            msg.add_alternative(body_html, subtype="html")
        else:
            msg.set_content(body_text or "")
        # Attachments: list of {filename, content, maintype, subtype}
        if attachments:
            for att in attachments:
                msg.add_attachment(
                    att["content"],
                    maintype=att.get("maintype", "application"),
                    subtype=att.get("subtype", "octet-stream"),
                    filename=att.get("filename", "attachment"),
                )
        return msg

    def send_email(
        self,
        to_addresses: Sequence[str] | str,
        subject: str,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        *,
        email_config: Optional[EmailConfig] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        timeout_seconds: float = 15.0,
    ) -> str:
        """
        Send an email via SMTP. Returns Message-ID (generated locally) on success.
        """
        if isinstance(to_addresses, str):
            to_list: List[str] = [to_addresses]
        else:
            to_list = list(to_addresses)
        if not to_list:
            raise ValueError("to_addresses is required")
        if not (body_text or body_html):
            raise ValueError("Either body_text or body_html must be provided")

        cfg = email_config
        if cfg is None:
            raise AlertingNotInitializedError("Email config is required")
        if not cfg.smtp_host or not cfg.smtp_port:
            raise AlertingNotInitializedError("SMTP host and port are required")

        msg = self._build_email_message(
            subject=subject,
            to_addresses=to_list,
            body_text=body_text,
            body_html=body_html,
            from_email=cfg.from_email,
            attachments=attachments,
        )

        try:
            context = ssl.create_default_context()
            if cfg.use_tls:
                with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout_seconds) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if cfg.username and cfg.password:
                        server.login(cfg.username, cfg.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, context=context, timeout=timeout_seconds) as server:
                    if cfg.username and cfg.password:
                        server.login(cfg.username, cfg.password)
                    server.send_message(msg)
            message_id = msg.get("Message-ID", "") or ""
            logger.debug("AlertService: Email sent to %s", to_list)
            return message_id
        except Exception as exc:
            logger.error("AlertService: send_email failed for %s: %s", to_list, exc)
            raise AlertingSendError("Failed to send email via SMTP") from exc

    # --- Fallback orchestration ---
    def send_with_fallback(
        self,
        *,
        email_first: bool,
        email_params: Optional[Dict[str, Any]] = None,
        sms_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Try one channel and fall back to the other on failure.
        Returns a dict with {primary: result|error, fallback: result|error}.
        """
        results: Dict[str, Any] = {}
        if email_first:
            try:
                mid = self.send_email(**(email_params or {}))
                results["email"] = {"ok": True, "id": mid}
                return results
            except Exception as exc:
                results["email"] = {"ok": False, "error": str(exc)}
                if sms_params:
                    sid = self.send_sms(**sms_params).message_sid
                    results["sms"] = {"ok": True, "id": sid}
                return results
        else:
            try:
                sid = self.send_sms(**(sms_params or {})).message_sid
                results["sms"] = {"ok": True, "id": sid}
                return results
            except Exception as exc:
                results["sms"] = {"ok": False, "error": str(exc)}
                if email_params:
                    mid = self.send_email(**email_params)
                    results["email"] = {"ok": True, "id": mid}
                return results
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


