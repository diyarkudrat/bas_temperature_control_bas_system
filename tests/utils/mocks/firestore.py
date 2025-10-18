"""Composable Firestore mocking helpers for tests.

Constraints:
- No network/emulator usage.
- Keep tests fast and isolated.
- Preserve current behavior/semantics.

API:
- Client/Collection
  - make_firestore_client(spec: bool = True) -> Mock
  - make_collection() -> Mock
  - attach_collection(client: Mock, name: str, collection: Mock) -> None
- Documents
  - make_doc(id: str, data: dict, exists: bool = True) -> Mock
  - set_document_get(collection: Mock, doc_id: str, *, exists: bool, data: dict | None = None, side_effect: Exception | None = None) -> None
- Queries (chaining: where → where → stream)
  - make_query(stream_docs: list[Mock] | None = None, side_effect: Exception | None = None) -> Mock
  - set_where_chain(collection: Mock, filters: list[tuple[str, str, object]], *, stream_docs: list[Mock] | None = None, side_effect: Exception | None = None) -> None
- Utilities
  - set_permission_denied(target: Mock, method: str) -> None
  - set_exception(target: Mock, method: str, exc: Exception) -> None
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Any
from unittest.mock import Mock

try:
    # Prefer real PermissionDenied for compatibility with code paths/tests
    from google.api_core.exceptions import PermissionDenied  # type: ignore
except Exception:  # pragma: no cover
    class PermissionDenied(Exception):  # type: ignore
        pass


# -------------------------
# Client / Collection
# -------------------------

def make_firestore_client(spec: bool = True) -> Mock:
    """Create a Firestore client mock.

    The client exposes `collection(name)` and `collections`.
    Collections attached via `attach_collection` are returned from `collection(name)`.
    """
    spec_attrs = ['collection', 'collections', '_fs_collections'] if spec else None
    client = Mock(spec_set=spec_attrs) if spec else Mock()
    # Internal mapping of name -> collection mock
    client._fs_collections: Dict[str, Mock] = {}

    def _collection_side_effect(name: str) -> Mock:
        if name in client._fs_collections:
            return client._fs_collections[name]
        raise KeyError(f"No mocked collection named '{name}' attached to client")

    client.collection.side_effect = _collection_side_effect
    # Provide a simple accessor for listing all attached collections
    client.collections = lambda: list(client._fs_collections.values())
    return client


def make_collection() -> Mock:
    """Create a collection/query-capable mock with restricted API."""
    # Firestore Collection supports where/order_by/limit/stream and document
    return Mock(spec_set=['document', 'where', 'order_by', 'limit', 'stream'])


def attach_collection(client: Mock, name: str, collection: Mock) -> None:
    """Attach a named collection mock to a client created by `make_firestore_client`."""
    if not hasattr(client, '_fs_collections'):
        client._fs_collections = {}
    client._fs_collections[name] = collection


# -------------------------
# Documents
# -------------------------

def make_doc(id: str, data: Dict[str, Any], exists: bool = True) -> Mock:
    """Create a document snapshot-like mock.

    Exposes attributes expected in tests: id, to_dict(), exists, reference.delete().
    """
    doc = Mock(spec_set=['id', 'to_dict', 'exists', 'reference', 'get', 'set', 'update'])
    # Snapshot fields
    doc.id = id
    doc.exists = exists
    doc.to_dict.return_value = data
    # Reference mock (supports delete invoked by code iterating query results)
    ref = Mock(spec_set=['delete'])
    doc.reference = ref
    return doc


def set_document_get(
    collection: Mock,
    doc_id: str,
    *,
    exists: bool,
    data: Optional[Dict[str, Any]] = None,
    side_effect: Optional[Exception] = None,
) -> None:
    """Wire collection.document(doc_id).get() to return a snapshot or raise.

    Also leaves .set/.update available for other tests to patch/use on the same doc_ref.
    """
    doc_ref = Mock(spec_set=['get', 'set', 'update', 'delete'])

    if side_effect is not None:
        doc_ref.get.side_effect = side_effect
    else:
        snapshot = make_doc(doc_id, data or {}, exists=exists)
        doc_ref.get.return_value = snapshot

    def _document_side_effect(requested_id: str) -> Mock:
        if requested_id == doc_id:
            return doc_ref
        # Return a fresh doc_ref for other ids to avoid leaking mocks across tests
        return Mock(spec_set=['get', 'set', 'update', 'delete'])

    collection.document.side_effect = _document_side_effect


# -------------------------
# Queries
# -------------------------

def make_query(
    stream_docs: Optional[List[Mock]] | None = None,
    side_effect: Optional[Exception] | None = None,
) -> Mock:
    """Create a query-like mock with .where/.order_by/.limit/.stream."""
    query = Mock(spec_set=['where', 'order_by', 'limit', 'stream'])

    # Default chaining returns self for order_by/limit for convenience
    query.order_by.return_value = query
    query.limit.return_value = query

    if side_effect is not None:
        query.stream.side_effect = side_effect
    else:
        query.stream.return_value = list(stream_docs or [])

    # Allow additional where chaining to return self by default
    query.where.return_value = query
    return query


def set_where_chain(
    collection: Mock,
    filters: List[Tuple[str, str, object]],
    *,
    stream_docs: Optional[List[Mock]] | None = None,
    side_effect: Optional[Exception] | None = None,
) -> None:
    """Wire exactly N where() calls according to `filters`.

    The final query's stream() yields `stream_docs` or raises `side_effect`.
    Argument values to where() are not asserted to keep tests resilient to minor query changes.
    """
    previous = collection
    num_filters = len(filters or [])
    if num_filters == 0:
        # No filters requested: wire collection.stream directly (rare)
        q = make_query(stream_docs=stream_docs, side_effect=side_effect)
        collection.stream = q.stream  # type: ignore[attr-defined]
        collection.order_by = q.order_by  # type: ignore[attr-defined]
        collection.limit = q.limit  # type: ignore[attr-defined]
        return

    # Create the chain of queries
    chain: List[Mock] = []
    for _ in range(num_filters):
        q = Mock(spec_set=['where', 'order_by', 'limit', 'stream'])
        # default chaining
        q.order_by.return_value = q
        q.limit.return_value = q
        chain.append(q)

    # Final link controls stream behavior
    final_q = chain[-1]
    if side_effect is not None:
        final_q.stream.side_effect = side_effect
    else:
        final_q.stream.return_value = list(stream_docs or [])

    # Wire where side effects to return the next link in the chain
    for idx in range(num_filters):
        next_link = chain[idx]

        def _make_where_return(q: Mock) -> Any:
            def _where_side_effect(*_args: Any, **_kwargs: Any) -> Mock:
                return q
            return _where_side_effect

        previous.where.side_effect = _make_where_return(next_link)  # type: ignore[assignment]
        previous = next_link

    # Ensure the last link supports additional where chaining to itself
    final_q.where.return_value = final_q


# -------------------------
# Utilities
# -------------------------

def set_permission_denied(target: Mock, method: str) -> None:
    """Set a PermissionDenied error on target.method."""
    getattr(target, method).side_effect = PermissionDenied("denied")


def set_exception(target: Mock, method: str, exc: Exception) -> None:
    """Set an exception side effect on target.method."""
    getattr(target, method).side_effect = exc


