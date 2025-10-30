"""Stdout sink emitting NDJSON for Cloud Run ingestion."""

from __future__ import annotations

import json
import sys
from threading import Lock
from typing import Mapping


class StdoutSink:
    """Write structured records to stdout as NDJSON."""

    def __init__(self, stream=None) -> None:
        self._stream = stream or sys.stdout
        self._lock = Lock()

    def emit(self, record: Mapping[str, object]) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


