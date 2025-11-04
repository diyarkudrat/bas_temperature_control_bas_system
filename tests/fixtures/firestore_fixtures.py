"""Firestore helper fixtures shared across unit suites."""

from __future__ import annotations

import os

import pytest


try:
    from tests.utils.mocks.firestore import (
        attach_collection,
        make_collection,
        make_doc,
        make_firestore_client,
        make_query,
        set_document_get,
        set_exception,
        set_permission_denied,
        set_where_chain,
    )
    _FS_HELPERS_AVAILABLE = True
except Exception:  # pragma: no cover - fallback when optional deps missing
    _FS_HELPERS_AVAILABLE = False
    attach_collection = None  # type: ignore[assignment]
    make_collection = None  # type: ignore[assignment]
    make_doc = None  # type: ignore[assignment]
    make_firestore_client = None  # type: ignore[assignment]
    make_query = None  # type: ignore[assignment]
    set_document_get = None  # type: ignore[assignment]
    set_exception = None  # type: ignore[assignment]
    set_permission_denied = None  # type: ignore[assignment]
    set_where_chain = None  # type: ignore[assignment]


if os.getenv("BAS_DISABLE_FS_HELPERS") == "1":
    _FS_HELPERS_AVAILABLE = False


def _require_helpers() -> None:
    if not _FS_HELPERS_AVAILABLE:
        pytest.skip("Firestore helpers not available")


@pytest.fixture
def fs_client():
    _require_helpers()
    return make_firestore_client()  # type: ignore[misc]


@pytest.fixture
def fs_collection():
    _require_helpers()
    return make_collection()  # type: ignore[misc]


@pytest.fixture
def query_with_docs():
    _require_helpers()
    d1 = make_doc("d1", {})  # type: ignore[misc]
    d2 = make_doc("d2", {})  # type: ignore[misc]
    return make_query([d1, d2])  # type: ignore[misc]


@pytest.fixture
def query_empty():
    _require_helpers()
    return make_query([])  # type: ignore[misc]


@pytest.fixture
def query_perm_denied():
    _require_helpers()
    from google.api_core.exceptions import PermissionDenied as _PermissionDenied  # type: ignore

    return make_query(side_effect=_PermissionDenied("denied"))  # type: ignore[misc]


@pytest.fixture
def query_exception():
    _require_helpers()
    return make_query(side_effect=Exception("boom"))  # type: ignore[misc]


