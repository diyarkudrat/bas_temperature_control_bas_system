"""Durable outbox repository backed by Firestore."""

from __future__ import annotations

from typing import Any, Dict, Optional

from google.cloud import firestore

from .base import OperationResult, TimestampedRepository
from .models import OutboxEvent, create_outbox_event


class OutboxRepository(TimestampedRepository):
    """Persist outbox events for downstream processing."""

    def __init__(self, client: firestore.Client):
        super().__init__(client, "outbox")
        self._required_fields = ["event_id", "topic", "status"]

    def enqueue(
        self,
        event: OutboxEvent,
        *,
        transaction: Optional[firestore.Transaction] = None,
    ) -> OperationResult[str]:
        try:
            data = event.to_dict()
            self._validate_required_fields(data, self._required_fields)
            payload = self._add_timestamps(data)
            doc_ref = self.collection.document(event.event_id)
            if transaction is None:
                doc_ref.set(payload)
            else:
                transaction.set(doc_ref, payload)
            return OperationResult(success=True, data=event.event_id)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("enqueue outbox event", exc)

    def get(self, event_id: str) -> OperationResult[OutboxEvent]:
        try:
            doc = self.collection.document(event_id).get()
            if not doc.exists:
                return OperationResult(success=False, error="Outbox event not found", error_code="NOT_FOUND")
            entity = create_outbox_event(doc.to_dict())
            entity.id = doc.id
            return OperationResult(success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("get outbox event", exc)

    def update(
        self,
        event_id: str,
        updates: Dict[str, Any],
        *,
        transaction: Optional[firestore.Transaction] = None,
    ) -> OperationResult[OutboxEvent]:
        try:
            payload = self._add_timestamps(dict(updates), include_updated=True)
            doc_ref = self.collection.document(event_id)
            if transaction is None:
                doc_ref.set(payload, merge=True)
                doc = doc_ref.get()
            else:
                transaction.set(doc_ref, payload, merge=True)
                doc = doc_ref.get(transaction=transaction)
            entity = create_outbox_event(doc.to_dict())
            entity.id = doc.id
            return OperationResult(success=True, data=entity)
        except Exception as exc:  # noqa: BLE001
            self._handle_firestore_error("update outbox event", exc)


__all__ = ["OutboxRepository"]


