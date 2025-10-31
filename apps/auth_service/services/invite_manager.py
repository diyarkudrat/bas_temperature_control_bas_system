"""Invite token management for organization onboarding."""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from collections import deque
from typing import Deque, Mapping, Optional

from adapters.db.firestore.models import Invite
from adapters.db.firestore.service_factory import FirestoreServiceFactory
from app_platform.config.auth import AuthConfig
from app_platform.contracts import InviteStatus

from apps.auth_service.http.schemas.org import InviteCreateRequest, InviteCreateResponse

from .auth0_mgmt import Auth0ManagementClient
from .exceptions import (
    InviteConflictError,
    InviteRateLimitError,
    ServiceConfigurationError,
    UpstreamServiceError,
)

logger = logging.getLogger(__name__)


class InviteService:
    """Create invites with hashed tokens and optional Auth0 integration."""

    def __init__(
        self,
        *,
        config: AuthConfig,
        firestore_factory: Optional[FirestoreServiceFactory],
        auth0_client: Optional[Auth0ManagementClient] = None,
    ) -> None:
        self._config = config
        self._firestore_factory = firestore_factory
        self._auth0_client = auth0_client
        self._repo = None
        if firestore_factory is not None:
            try:
                self._repo = firestore_factory.get_invite_service()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to initialize Firestore invite repository: %s", exc)
        self._window_seconds = max(60, int(config.invite_quota_window_minutes or 60) * 60)
        self._quota = max(1, int(config.invite_quota_per_tenant or 20))
        self._ttl_hours = max(1, int(config.invite_ttl_hours or 72))
        self._lock = threading.RLock()
        self._per_tenant_windows: dict[str, Deque[float]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._repo) and bool(self._config.org_signup_v2_enabled)

    def create_invite(self, request: InviteCreateRequest) -> InviteCreateResponse:
        if not self.enabled:
            raise ServiceConfigurationError("Invite service is not configured")

        self._enforce_quota(request.tenant_id)

        existing = self._repo.get_active_invite(request.tenant_id, request.email)  # type: ignore[union-attr]
        if existing:
            raise InviteConflictError("Active invite already exists for tenant/email")

        invite_id = secrets.token_urlsafe(16)
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        issued_at = int(time.time())
        expires_at = issued_at + self._ttl_hours * 3600

        invite = Invite(
            invite_id=invite_id,
            tenant_id=request.tenant_id,
            email=request.email,
            role=request.role.value,
            status=InviteStatus.PENDING.value,
            token_hash=token_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            invited_by=request.invited_by,
            metadata=dict(request.metadata or {}),
        )

        result = self._repo.create(invite)  # type: ignore[union-attr]
        if not result or not getattr(result, "success", False):
            raise UpstreamServiceError("Failed to persist invite record")

        self._post_create_hooks(request, invite_id, invite)

        logger.info(
            "Invite token minted",
            extra={
                "tenant_id": request.tenant_id,
                "email_hash": hashlib.sha256(request.email.encode("utf-8")).hexdigest()[:12],
                "invite_id": invite_id,
                "expires_at": expires_at,
                "send_email": request.send_email,
            },
        )

        return InviteCreateResponse(
            invite_id=invite_id,
            status=InviteStatus.PENDING,
            token=raw_token,
        )

    def _post_create_hooks(self, request: InviteCreateRequest, invite_id: str, invite: Invite) -> None:
        auth0_user_id = None
        metadata = request.metadata or {}
        if isinstance(metadata, Mapping):
            auth0_user_id = metadata.get("auth0_user_id")

        if not auth0_user_id or not self._auth0_client or not self._auth0_client.enabled:
            return

        try:
            self._auth0_client.block_user(str(auth0_user_id), reason="pending_invite")
            app_metadata = {
                "tenantId": request.tenant_id,
                "inviteId": invite_id,
                "inviteStatus": invite.status,
            }
            existing_meta = metadata.get("app_metadata") if isinstance(metadata, Mapping) else None
            if isinstance(existing_meta, Mapping):
                app_metadata.update({str(k): v for k, v in existing_meta.items()})
            self._auth0_client.update_app_metadata(str(auth0_user_id), app_metadata)
        except UpstreamServiceError as exc:
            logger.warning(
                "Auth0 management integration failed for invite",
                extra={
                    "tenant_id": request.tenant_id,
                    "invite_id": invite_id,
                    "error": str(exc),
                },
            )

    def _enforce_quota(self, tenant_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            window = self._per_tenant_windows.setdefault(tenant_id, deque())
            while window and now - window[0] > self._window_seconds:
                window.popleft()
            if len(window) >= self._quota:
                logger.info(
                    "Invite rate limit reached",
                    extra={"tenant_id": tenant_id, "quota": self._quota, "window_seconds": self._window_seconds},
                )
                raise InviteRateLimitError("Invite quota exceeded for tenant")
            window.append(now)


