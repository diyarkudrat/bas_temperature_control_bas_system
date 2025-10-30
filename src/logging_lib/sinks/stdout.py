"""Stdout sink emitting NDJSON for Cloud Run ingestion."""

from __future__ import annotations

import json
import sys
import threading
from typing import Mapping

from ..config import LoggingSettings


class StdoutSink:
    """Write structured records to stdout as NDJSON."""

    def __init__(self, settings: LoggingSettings, stream=None) -> None:
        """Initialize the stdout sink with a given settings and stream."""
        
        self._settings = settings # The settings for the sink
        self._stream = stream or sys.stdout # The stream to write to
        self._lock = threading.Lock() # The lock for the sink

    def emit(self, record: Mapping[str, object]) -> None:
        """Emit a record to the stdout sink."""
        
        payload = dict(record)

        context = payload.get("context")

        trace_id = None
        span_id = None

        if isinstance(context, dict):
            trace_id = context.get("trace_id") or payload.get("trace_id")
            span_id = context.get("span_id") or payload.get("span_id")

        project = self._settings.gcl_project

        if trace_id and project:
            payload.setdefault(
                "logging.googleapis.com/trace",
                f"projects/{project}/traces/{trace_id}",
            )

        if span_id:
            payload.setdefault("logging.googleapis.com/spanId", span_id)

        payload.setdefault("severity", payload.get("level", "INFO"))

        line = json.dumps(payload, separators=(",", ":"))
        
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


