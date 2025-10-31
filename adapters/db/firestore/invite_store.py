"""Firestore repository for invite documents."""

from __future__ import annotations

from typing import Any, Dict, Optional

from google.cloud import firestore

from app_platform.contracts import InviteStatus

from .base import OperationResult, TimestampedRepository, ValidationError
from .models import Invite, create_invite


class InviteRepository(TimestampedRepository):
    """Repository wrapper for the top-level invites collection."""

    def __init__(self, client: firestore.Client):
        super().__init__(client, "invites")
        self._required_fields = ["invite_id", "tenant_id", "email", "role", "status"]

    def create(self, entity: Invite) -> OperationResult[str]:
        try:
            data = entity.to_dict()
            self._validate_required_fields(data, self._required_fields)
            payload = self._add_timestamps(data)
            self.collection.document(entity.invite_id).set(payload)
            return OperationResult(success=True, data=entity.invite_id)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("create invite", exc)

    def get_by_id(self, invite_id: str) -> OperationResult[Invite]:
        try:
            doc = self.collection.document(invite_id).get()
            if not doc.exists:
                return OperationResult(success=False, error="Invite not found", error_code="NOT_FOUND")
            invite = create_invite(doc.to_dict())
            invite.id = doc.id
            return OperationResult(success=True, data=invite)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get invite", exc)

    def get_active_invite(self, tenant_id: str, email: str) -> Optional[Invite]:
        try:
            query = (
                self.collection.where("tenant_id", "==", tenant_id)
                .where("email", "==", email.lower())
                .where("status", "in", [InviteStatus.PENDING.value, InviteStatus.SENT.value])
                .limit(1)
            )
            docs = list(query.stream())
            if not docs:
                return None
            doc = docs[0]
            invite = create_invite(doc.to_dict())
            invite.id = doc.id
            return invite
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("query active invite", exc)

    def update(self, invite_id: str, updates: Dict[str, Any]) -> OperationResult[Invite]:
        try:
            payload = self._add_timestamps(dict(updates), include_updated=True)
            doc_ref = self.collection.document(invite_id)
            doc_ref.set(payload, merge=True)
            doc = doc_ref.get()
            invite = create_invite(doc.to_dict())
            invite.id = doc.id
            return OperationResult(success=True, data=invite)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("update invite", exc)

    def mark_redeemed(self, invite_id: str, *, redeemed_by: str, redeemed_at: int) -> OperationResult[Invite]:
        return self.update(
            invite_id,
            {
                "status": InviteStatus.REDEEMED.value,
                "redeemed_by": redeemed_by,
                "redeemed_at": redeemed_at,
            },
        )

    def expire_invite(self, invite_id: str) -> OperationResult[Invite]:
        return self.update(invite_id, {"status": InviteStatus.EXPIRED.value})

    def delete(self, invite_id: str) -> OperationResult[bool]:
        try:
            self.collection.document(invite_id).delete()
            return OperationResult(success=True, data=True)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("delete invite", exc)


__all__ = ["InviteRepository"]


