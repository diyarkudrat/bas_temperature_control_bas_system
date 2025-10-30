"""Google Cloud Logging API sink."""

from __future__ import annotations

import json
import sys
from typing import Mapping

try:  # pragma: no cover - optional dependency
    from google.cloud import logging as gcl_logging
    from google.api_core.exceptions import GoogleAPICallError
except Exception as exc:  # pragma: no cover - optional dependency
    gcl_logging = None
    GoogleAPICallError = Exception
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class GoogleCloudLoggingSink:
    """Google Cloud Logging API sink."""

    def __init__(
        self,
        *,
        project: str | None,
        log_name: str,
        service: str,
        env: str,
    ) -> None:
        """Initialize the Google Cloud Logging API sink with a given project, log name, service, and environment."""

        if gcl_logging is None:
            raise RuntimeError(
                "google-cloud-logging is required for GoogleCloudLoggingSink"
            ) from _IMPORT_ERROR

        self._client = gcl_logging.Client(project=project) # The client for the sink
        self._logger = self._client.logger(log_name) # The logger for the sink
        self._project = project or self._client.project # The project for the sink
        self._labels = {"service": service, "env": env} # The labels for the sink
        self._resource = {
            "type": "global",
            "labels": {"project_id": self._project}, # The resource for the sink
        }

    def emit(self, record: Mapping[str, object]) -> None:
        """Emit a record to the Google Cloud Logging API sink."""
        
        payload = dict(record)
        context = payload.get("context")

        if isinstance(context, dict):
            trace_id = context.get("trace_id") or payload.get("trace_id")

            if trace_id:
                payload.setdefault(
                    "logging.googleapis.com/trace",
                    f"projects/{self._project}/traces/{trace_id}",
                )
                
            span_id = context.get("span_id") or payload.get("span_id")
            if span_id:
                payload.setdefault("logging.googleapis.com/spanId", span_id)

        severity = str(payload.get("level", "INFO"))

        try:
            self._logger.log_struct(
                payload,
                severity=severity,
                resource=self._resource,
                labels=self._labels,
            )
        except GoogleAPICallError as exc:  # pragma: no cover - network error
            print(
                "google cloud logging emission failed: " + json.dumps(payload),
                file=sys.stderr,
            )
            raise exc


