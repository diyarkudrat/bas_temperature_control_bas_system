"""Invite token management for organization onboarding."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import threading
import time
from collections import deque
from typing import Deque, Mapping, Optional

from adapters.db.firestore.models import Invite, OutboxEvent
from adapters.db.firestore.service_factory import FirestoreServiceFactory
from app_platform.config.auth import AuthConfig
from app_platform.contracts import InviteStatus
from app_platform.security import (
    ReplayCache,
    ServiceTokenError,
    issue_service_jwt,
    load_replay_cache_from_env,
    load_service_keyset_from_env,
)

from apps.auth_service.http.schemas.org import (
    InviteAcceptRequest,
    InviteAcceptResponse,
    InviteCreateRequest,
    InviteCreateResponse,
)

from .auth0_mgmt import Auth0ManagementClient
from .exceptions import (
    InviteConflictError,
    InviteExpiredError,
    InviteNotFoundError,
    InviteRateLimitError,
    InviteTokenError,
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
        self._client = getattr(firestore_factory, "client", None) if firestore_factory else None
        self._outbox_repo = None
        if firestore_factory is not None:
            try:
                self._repo = firestore_factory.get_invite_service()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to initialize Firestore invite repository: %s", exc)
            try:
                self._outbox_repo = firestore_factory.get_outbox_service()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to initialize outbox repository: %s", exc)
        self._window_seconds = max(60, int(config.invite_quota_window_minutes or 60) * 60)
        self._quota = max(1, int(config.invite_quota_per_tenant or 20))
        self._ttl_hours = max(1, int(config.invite_ttl_hours or 72))
        self._lock = threading.RLock()
        self._per_tenant_windows: dict[str, Deque[float]] = {}

        prefix = os.getenv("INVITE_ACCEPT_JWT_PREFIX", "REQUEST_JWT") or "REQUEST_JWT"
        try:
            self._accept_keyset = load_service_keyset_from_env(prefix=prefix)
        except ServiceTokenError as exc:
            logger.warning("Invite acceptance keyset unavailable: %s", exc)
            self._accept_keyset = None
        else:
            try:
                self._accept_replay_cache: Optional[ReplayCache] = load_replay_cache_from_env(
                    prefix=prefix,
                    namespace="invite-accept",
                )
            except Exception:  # noqa: BLE001
                self._accept_replay_cache = None
        if not hasattr(self, "_accept_replay_cache"):
            self._accept_replay_cache = None

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

    def accept_invite(self, request: InviteAcceptRequest) -> InviteAcceptResponse:
        if not self.enabled:
            raise ServiceConfigurationError("Invite service is not configured")

        if self._repo is None or self._firestore_factory is None or self._client is None:
            raise ServiceConfigurationError("Invite persistence unavailable")

        record = self._repo.get_by_id(request.invite_id)  # type: ignore[union-attr]
        if not record or not getattr(record, "success", False) or record.data is None:
            raise InviteNotFoundError("Invite not found")

        invite: Invite = record.data
        if invite.tenant_id != request.tenant_id:
            raise InviteTokenError("Invite tenant mismatch")

        now_seconds = int(time.time())
        if invite.expires_at and now_seconds > int(invite.expires_at):
            try:
                self._repo.expire_invite(invite.invite_id)  # type: ignore[union-attr]
            except Exception:
                pass
            raise InviteExpiredError("Invite expired")

        normalized_status = str(invite.status or "").lower()
        if normalized_status not in {
            InviteStatus.PENDING.value,
            InviteStatus.SENT.value,
            InviteStatus.REDEEMED.value,
        }:
            raise InviteTokenError("Invite cannot be accepted in its current state")

        token_hash = hashlib.sha256(request.token.encode("utf-8")).hexdigest()
        if invite.token_hash != token_hash:
            raise InviteTokenError("Invite token invalid")

        invite_metadata = invite.metadata or {}
        member_id = str(invite_metadata.get("memberId") or f"invitee_{invite.invite_id}")
        accept_result = self._apply_acceptance_transaction(invite, member_id, now_seconds)

        try:
            self._repo.mark_redeemed(
                invite.invite_id,
                redeemed_by=member_id,
                redeemed_at=now_seconds,
            )  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to mark invite redeemed",
                extra={"invite_id": invite.invite_id, "error": str(exc)},
            )

        acceptance_token = self._issue_acceptance_token(invite, member_id)

        logger.info(
            "Invite accepted",
            extra={
                "tenant_id": invite.tenant_id,
                "invite_id": invite.invite_id,
                "member_id": member_id,
            },
        )

        return InviteAcceptResponse(
            tenant_id=invite.tenant_id,
            member_id=member_id,
            status=accept_result,
            token=acceptance_token,
        )

    def _apply_acceptance_transaction(self, invite: Invite, member_id: str, accepted_at_s: int) -> str:
        client = self._client
        if client is None:
            raise ServiceConfigurationError("Firestore client unavailable")

        tenant_ref = client.collection("tenants").document(invite.tenant_id)
        member_ref = tenant_ref.collection("members").document(member_id)
        sentinel_ref = client.collection("unique_members").document(self._sentinel_key(invite.tenant_id, invite.email))
        audit_collection = client.collection("audit_log")

        accepted_at_ms = accepted_at_s * 1000
        state: dict[str, str] = {"status": "updated"}

        transaction = client.transaction()

        def _txn(tx) -> None:
            tenant_snapshot = tenant_ref.get(transaction=tx)
            if not tenant_snapshot.exists:
                raise InviteNotFoundError("Tenant not found for invite acceptance")

            member_snapshot = member_ref.get(transaction=tx)
            member_data = member_snapshot.to_dict() if member_snapshot.exists else {}
            metadata = dict(member_data.get("metadata") or {})

            existing_invite_id = metadata.get("inviteId")
            current_status = str(member_data.get("status") or "").lower()
            if existing_invite_id == invite.invite_id and current_status == "active":
                state["status"] = "noop"
                return

            metadata.update(
                {
                    "inviteId": invite.invite_id,
                    "inviteAcceptedAt": accepted_at_ms,
                }
            )

            member_payload = {
                "tenant_id": invite.tenant_id,
                "user_id": member_id,
                "email": invite.email.lower(),
                "role": invite.role,
                "status": "active",
                "accepted_at": accepted_at_ms,
                "metadata": metadata,
                "updated_at": accepted_at_ms,
            }
            tx.set(member_ref, member_payload, merge=True)

            tx.delete(sentinel_ref)

            tenant_data = tenant_snapshot.to_dict() or {}
            counters = dict(tenant_data.get("counters") or {})
            counters["pendingMembers"] = max(0, int(counters.get("pendingMembers", 0)) - 1)
            counters["members"] = int(counters.get("members", 0)) + 1
            tx.update(
                tenant_ref,
                {
                    "counters": counters,
                    "updated_at": accepted_at_ms,
                },
            )

            audit_doc = {
                "timestamp_ms": accepted_at_ms,
                "utc_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(accepted_at_s)),
                "event_type": "INVITE_ACCEPTED",
                "user_id": member_id,
                "username": invite.email.lower(),
                "ip_address": None,
                "details": {
                    "tenantId": invite.tenant_id,
                    "inviteId": invite.invite_id,
                },
                "tenant_id": invite.tenant_id,
            }
            tx.set(audit_collection.document(), audit_doc)

            if self._outbox_repo is not None:
                outbox_event = OutboxEvent(
                    event_id=f"tenant-invite-accepted::{invite.invite_id}",
                    topic="tenant.invite_accepted",
                    payload={
                        "tenantId": invite.tenant_id,
                        "inviteId": invite.invite_id,
                        "memberId": member_id,
                        "email": invite.email,
                    },
                    status="pending",
                    available_at=accepted_at_s,
                )
                self._outbox_repo.enqueue(outbox_event, transaction=tx)

        transaction.call(_txn)

        return state.get("status", "updated")

    def _issue_acceptance_token(self, invite: Invite, member_id: str) -> Optional[str]:
        if self._accept_keyset is None:
            return None

        additional_claims = {
            "tenant_id": invite.tenant_id,
            "member_id": member_id,
            "email": invite.email.lower(),
            "role": invite.role,
        }

        audience = os.getenv("INVITE_ACCEPT_JWT_AUDIENCE") or os.getenv("SERVICE_JWT_EXPECTED_AUDIENCE") or "bas-api"
        issuer = os.getenv("INVITE_ACCEPT_JWT_ISSUER") or "auth-service"

        ttl_env = os.getenv("INVITE_ACCEPT_JWT_TTL", "60")
        try:
            ttl_seconds = int(ttl_env)
        except ValueError:
            ttl_seconds = 60
        ttl_seconds = min(60, max(30, ttl_seconds))

        try:
            issued = issue_service_jwt(
                self._accept_keyset,
                subject="auth.invite.accepted",
                audience=audience,
                issuer=issuer,
                ttl_seconds=ttl_seconds,
                additional_claims=additional_claims,
            )
        except ServiceTokenError as exc:
            logger.warning("Failed to issue invite acceptance token: %s", exc)
            return None

        if self._accept_replay_cache is not None:
            try:
                self._accept_replay_cache.check_and_store(
                    f"invite-accept:{issued.claims.get('jti')}", expires_at=issued.expires_at
                )
            except Exception:
                pass

        return issued.token

    @staticmethod
    def _sentinel_key(tenant_id: str, email: str) -> str:
        normalized_email = (email or "").strip().lower()
        digest = hashlib.sha256(f"{tenant_id}::{normalized_email}".encode("utf-8")).hexdigest()
        return f"{tenant_id}__{digest[:32]}"


