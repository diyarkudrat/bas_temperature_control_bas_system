"""Firestore-backed idempotency key repository."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from google.cloud import firestore

from .base import OperationResult, TimestampedRepository
from .models import IdempotencyKey, create_idempotency_key


class IdempotencyKeyRepository(TimestampedRepository):
    """Durable idempotency key store."""

    def __init__(self, client: firestore.Client):
        """Initialize the idempotency key repository."""

        super().__init__(client, "idempotency_keys")
        self._required_fields = ["key", "request_hash", "status"] # Required fields

    def create(self, entity: IdempotencyKey) -> OperationResult[str]:
        """Create an idempotency key."""

        try:
            data = entity.to_dict()
            self._validate_required_fields(data, self._required_fields)

            payload = self._add_timestamps(data)
            self.collection.document(entity.key).set(payload)

            return OperationResult[str](success=True, data=entity.key)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("create idempotency key", exc)

    def get_by_id(self, key: str) -> OperationResult[IdempotencyKey]:
        """Get an idempotency key by ID."""

        try:
            doc = self.collection.document(key).get()

            if not doc.exists:
                return OperationResult[IdempotencyKey](success=False, error="Idempotency key not found", error_code="NOT_FOUND")

            entity = create_idempotency_key(doc.to_dict())
            entity.id = doc.id

            return OperationResult[IdempotencyKey](success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get idempotency key", exc)

    def update(self, key: str, updates: Dict[str, Any]) -> OperationResult[IdempotencyKey]:
        """Update an idempotency key."""

        try:
            payload = self._add_timestamps(dict[str, Any](updates), include_updated=True)
            doc_ref = self.collection.document(key)

            doc_ref.set(payload, merge=True)

            doc = doc_ref.get()
            entity = create_idempotency_key(doc.to_dict())
            entity.id = doc.id

            return OperationResult[IdempotencyKey](success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("update idempotency key", exc)

    def delete(self, key: str) -> OperationResult[bool]:
        """Delete an idempotency key."""

        try:
            self.collection.document(key).delete()

            return OperationResult[bool](success=True, data=True)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("delete idempotency key", exc)

    # Domain helpers -------------------------------------------------------

    def reserve(
        self,
        key: str,
        *,
        method: str,
        path: str,
        request_hash: str,
        tenant_id: Optional[str],
        expires_at: int,
    ) -> Tuple[str, IdempotencyKey]:
        """Reserve an idempotency key."""

        try:
            doc_ref = self.collection.document(key)

            def _txn(transaction: firestore.Transaction) -> Tuple[str, IdempotencyKey]:
                """Transaction function to reserve an idempotency key."""

                snapshot = doc_ref.get(transaction=transaction)
                if snapshot.exists:
                    entity = create_idempotency_key(snapshot.to_dict())
                    entity.id = snapshot.id
                    return entity.status, entity

                payload = self._add_timestamps(
                    {
                        "key": key,
                        "status": "in_progress",
                        "method": method,
                        "path": path,
                        "request_hash": request_hash,
                        "tenant_id": tenant_id,
                        "expires_at": expires_at,
                    }
                )

                transaction.set(doc_ref, payload)

                entity = create_idempotency_key(payload)
                entity.id = key

                return "reserved", entity

            txn = self.client.transaction()

            return txn.call(_txn)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("reserve idempotency key", exc)

    def record_response(
        self,
        key: str,
        *,
        status_code: int,
        body_base64: str,
        headers: Dict[str, str],
    ) -> OperationResult[IdempotencyKey]:
        """Record a response for an idempotency key."""
        
        return self.update(
            key,
            {
                "status": "completed",
                "status_code": status_code,
                "response_body": body_base64,
                "response_headers": headers,
            },
        )


__all__ = ["IdempotencyKeyRepository"]


