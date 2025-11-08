"""Firestore repository for tenant aggregates."""

from __future__ import annotations

from typing import Any, Dict, Optional

from google.cloud import firestore

from app_platform.contracts import TenantStatus

from .base import OperationResult, TimestampedRepository, ValidationError
from .models import Tenant, create_tenant


class TenantRepository(TimestampedRepository):
    """Tenant repository encapsulating Firestore access patterns."""

    def __init__(self, client: firestore.Client):
        super().__init__(client, "tenants")
        self._required_fields = ["tenant_id", "name", "status"]

    # CRUD -----------------------------------------------------------------

    def create(self, entity: Tenant) -> OperationResult[str]:
        """Create a tenant."""

        try:
            data = entity.to_dict()
            self._validate_required_fields(data, self._required_fields)

            doc_id = entity.tenant_id
            payload = self._add_timestamps(data)

            self.collection.document(doc_id).set(payload)

            return OperationResult[str](success=True, data=doc_id)
        except Exception as exc:  # noqa: BLE001 - delegated to handler
            self._handle_firestore_error("create tenant", exc)

    def get_by_id(self, tenant_id: str) -> OperationResult[Tenant]:
        """Get a tenant by ID."""

        try:
            doc = self.collection.document(tenant_id).get()
            if not doc.exists:
                return OperationResult[Tenant](success=False, error="Tenant not found", error_code="NOT_FOUND")

            entity = create_tenant(doc.to_dict())
            entity.id = doc.id

            return OperationResult[Tenant](success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get tenant", exc)

    def get_by_slug(self, slug: str) -> OperationResult[Tenant]:
        """Get a tenant by slug."""
        
        try:
            query = (self.collection.where("slug", "==", slug).limit(1))

            docs = list[Any](query.stream())
            if not docs:
                return OperationResult[Tenant](success=False, error="Tenant not found", error_code="NOT_FOUND")

            doc = docs[0]
            entity = create_tenant(doc.to_dict())
            entity.id = doc.id

            return OperationResult[Tenant](success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get tenant by slug", exc)

    def update(self, tenant_id: str, updates: Dict[str, Any]) -> OperationResult[Tenant]:
        """Update a tenant."""
        
        try:
            payload = self._add_timestamps(dict[str, Any](updates), include_updated=True)
            doc_ref = self.collection.document(tenant_id)
            doc_ref.set(payload, merge=True)

            doc = doc_ref.get()

            entity = create_tenant(doc.to_dict())
            entity.id = doc.id

            return OperationResult[Tenant](success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("update tenant", exc)

    def delete(self, tenant_id: str) -> OperationResult[bool]:
        """Delete a tenant."""

        try:
            self.collection.document(tenant_id).delete()

            return OperationResult(success=True, data=True)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("delete tenant", exc)

    # Domain helpers -------------------------------------------------------

    def update_status(self, tenant_id: str, status: TenantStatus) -> OperationResult[Tenant]:
        """Update the status of a tenant."""

        if status not in TenantStatus:
            raise ValidationError(f"Unsupported tenant status: {status}")

        return self.update(tenant_id, {"status": status.value})

    def update_limits(self, tenant_id: str, limits: Dict[str, Any]) -> OperationResult[Tenant]:
        """Update the limits of a tenant."""
        return self.update(tenant_id, {"limits": limits})

    def increment_counter(self, tenant_id: str, counter: str, *, delta: int = 1) -> OperationResult[int]:
        """Increment a counter for a tenant."""

        if delta == 0:
            return OperationResult(success=True, data=0)

        try:
            doc_ref = self.collection.document(tenant_id)

            def _txn(transaction: firestore.Transaction) -> int:
                """Transaction function to increment a counter for a tenant."""

                snapshot = doc_ref.get(transaction=transaction)
                if not snapshot.exists:
                    raise ValidationError("Tenant not found")

                counters = snapshot.get("counters") or {}
                current = int(counters.get(counter, 0))
                next_value = max(0, current + delta)

                transaction.update(doc_ref, {f"counters.{counter}": next_value})

                return next_value

            transaction = self.client.transaction()
            result = transaction.call(_txn)

            return OperationResult(success=True, data=result)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("increment tenant counter", exc)


__all__ = ["TenantRepository"]