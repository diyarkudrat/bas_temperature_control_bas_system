"""Firestore data access layer modules.

Provides a small initializer that respects emulator environment variables
to create a client suitable for local development without cloud access.
"""

from __future__ import annotations

import os
from typing import Optional

try:
    from google.cloud import firestore  # type: ignore
except Exception:  # pragma: no cover - optional at runtime
    firestore = None  # type: ignore


def init_client(
    project_id: Optional[str] = None,
    emulator_host: Optional[str] = None,
):
    """Create a Firestore client, honoring emulator settings when provided.

    Args:
        project_id: Explicit GCP project id; optional in emulator mode.
        emulator_host: Host:port of firestore emulator; if None, checks env.

    Returns:
        A firestore.Client instance, or None if library unavailable.
    """
    client = None
    if firestore is None:
        return client

    # Prefer explicit values; fall back to environment
    use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
    emulator = emulator_host or os.getenv("FIRESTORE_EMULATOR_HOST")

    if use_emulators and emulator:
        os.environ["FIRESTORE_EMULATOR_HOST"] = emulator
        pid = project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or "local-dev"
        client = firestore.Client(project=pid)
    else:
        # Production path: ensure emulator var is not set accidentally
        if "FIRESTORE_EMULATOR_HOST" in os.environ:
            del os.environ["FIRESTORE_EMULATOR_HOST"]

        if project_id:
            client = firestore.Client(project=project_id)
        else:
            # Fallback to default discovery/ADC
            client = firestore.Client()
    return client
