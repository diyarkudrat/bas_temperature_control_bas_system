"""In-memory sink useful for debugging and tests."""

from __future__ import annotations

from typing import List, Mapping


class InMemorySink:
    def __init__(self) -> None:
        self.records: List[Mapping[str, object]] = []

    def emit(self, record: Mapping[str, object]) -> None:
        self.records.append(dict(record))


