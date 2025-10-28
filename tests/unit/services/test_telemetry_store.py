from __future__ import annotations

import time

from adapters.db.firestore.telemetry_store import TelemetryRepository


class _NoopDoc:
    def __init__(self):
        self.id = "doc1"


class _MockCollection:
    def __init__(self):
        self._added = []

    def add(self, data):
        self._added.append(data)
        return None, _NoopDoc()

    def stream(self):  # unused
        return []


class _MockClient:
    def __init__(self):
        self._coll = {}

    def collection(self, name: str):
        if name not in self._coll:
            self._coll[name] = _MockCollection()
        return self._coll[name]


def test_store_auth_event_success():
    repo = TelemetryRepository(_MockClient())
    ok = repo.store_auth_event({"type": "JWT", "outcome": "SUCCESS", "endpoint": "/api/x"})
    assert ok is True
    repo.wait_auth_events_drained(0.2)
    # Ensure writes happened
    coll = repo.client.collection('auth_events')
    assert len(coll._added) >= 1


def test_store_auth_event_failure_queue_full(monkeypatch):
    repo = TelemetryRepository(_MockClient())
    # Fill queue quickly by setting tiny maxsize via monkeypatch (not available). Instead, enqueue many and stop worker temporarily.
    # Simulate full by directly replacing queue with size 0
    class _ZeroQueue:
        def put_nowait(self, item):  # noqa: ARG002
            from queue import Full
            raise Full()

    monkeypatch.setattr(repo, "_auth_events_queue", _ZeroQueue())
    ok = repo.store_auth_event({"type": "JWT", "outcome": "FAILURE"})
    assert ok is False


