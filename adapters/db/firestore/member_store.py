"""Firestore repository for tenant members."""

from adapters.db.firestore.models import TenantMember


from __future__ import annotations

from typing import Any, Dict, List, Optional

from google.cloud import firestore

from app_platform.contracts import MemberRole

from .base import OperationResult, TimestampedRepository, ValidationError
from .models import TenantMember, create_tenant_member


class TenantMemberRepository(TimestampedRepository):
    """Repository for tenant members stored under tenants/{tenant}/members."""

    def __init__(self, client: firestore.Client):
        super().__init__(client, "tenants")
        self._required_fields = ["tenant_id", "user_id", "email", "role"]

    def _members_collection(self, tenant_id: str):
        """Get the members collection for a tenant."""

        return self.collection.document(tenant_id).collection("members")

    def create(self, entity: TenantMember) -> OperationResult[str]:
        """Create a tenant member."""

        try:
            data = entity.to_dict()

            self._validate_required_fields(data, self._required_fields)

            members = self._members_collection(entity.tenant_id)
            payload = self._add_timestamps(data)
            members.document(entity.user_id).set(payload)

            return OperationResult(success=True, data=entity.user_id)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("create member", exc)

    def get(self, tenant_id: str, user_id: str) -> OperationResult[TenantMember]:
        """Get a tenant member by tenant ID and user ID."""

        try:
            doc = self._members_collection(tenant_id).document(user_id).get()

            if not doc.exists:
                return OperationResult[TenantMember](success=False, error="Member not found", error_code="NOT_FOUND")

            member = create_tenant_member(doc.to_dict())
            member.id = doc.id

            return OperationResult[TenantMember](success=True, data=member)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get member", exc)

    def delete(self, tenant_id: str, user_id: str) -> OperationResult[bool]:
        """Delete a tenant member by tenant ID and user ID."""

        try:
            self._members_collection(tenant_id).document(user_id).delete()

            return OperationResult(success=True, data=True)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("delete member", exc)

    def update(self, tenant_id: str, user_id: str, updates: Dict[str, Any]) -> OperationResult[TenantMember]:
        """Update a tenant member by tenant ID and user ID."""

        try:
            payload = self._add_timestamps(dict(updates), include_updated=True)

            doc_ref = self._members_collection(tenant_id).document(user_id)
            doc_ref.set(payload, merge=True)
            doc = doc_ref.get()

            member = create_tenant_member(doc.to_dict())
            member.id = doc.id

            return OperationResult[TenantMember](success=True, data=member)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("update member", exc)

    def list_by_role(self, tenant_id: str, role: MemberRole) -> OperationResult[List[TenantMember]]:
        """List tenant members by role."""

        try:
            query = self._members_collection(tenant_id).where("role", "==", role.value)
            docs = list[Any](query.stream())
            members = []

            for doc in docs:
                member = create_tenant_member(doc.to_dict())
                member.id = doc.id
                members.append(member)

            return OperationResult[List[TenantMember]](success=True, data=members)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("list members by role", exc)

    def list_pending(self, tenant_id: str) -> OperationResult[List[TenantMember]]:
        """List pending tenant members by tenant ID."""

        try:
            query = self._members_collection(tenant_id).where("status", "==", "pending")
            docs = list[Any](query.stream())
            members = []

            for doc in docs:
                member = create_tenant_member(doc.to_dict())
                member.id = doc.id
                members.append(member)

            return OperationResult[List[TenantMember]](success=True, data=members)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("list pending members", exc)

    def set_verified(self, tenant_id: str, user_id: str, *, timestamp_ms: int) -> OperationResult[TenantMember]:
        """Set a tenant member as verified."""
        
        return self.update(
            tenant_id,
            user_id,
            {
                "status": "active",
                "accepted_at": timestamp_ms,
            },
        )


__all__ = ["TenantMemberRepository"]


