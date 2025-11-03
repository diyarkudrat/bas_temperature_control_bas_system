"""In-memory sink for diagnostics and testing."""

from __future__ import annotations

from typing import List, Mapping


class InMemorySink:
    """In-memory sink for diagnostics and testing."""

    def __init__(self) -> None:
        """Initialize the in-memory sink."""

        self.records: List[Mapping[str, object]] = [] # The records to store

    def emit(self, record: Mapping[str, object]) -> None:
        """Emit a record to the in-memory sink."""

        self.records.append(dict(record))


