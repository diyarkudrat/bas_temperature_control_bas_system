from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class FirestoreBudgets:
    """Firestore timeouts and retries."""

    read_timeout_ms: int = 50
    write_timeout_ms: int = 70
    retries: int = 2
    base_backoff_ms: int = 10
    max_backoff_ms: int = 100

    @classmethod
    def from_env(cls) -> "FirestoreBudgets":
        """Load configuration from environment variables."""
        
        return cls(
            read_timeout_ms=int(os.getenv("BAS_FS_READ_TIMEOUT_MS", "50")),
            write_timeout_ms=int(os.getenv("BAS_FS_WRITE_TIMEOUT_MS", "70")),
            retries=int(os.getenv("BAS_FS_RETRIES", "2")),
            base_backoff_ms=int(os.getenv("BAS_FS_BACKOFF_BASE_MS", "10")),
            max_backoff_ms=int(os.getenv("BAS_FS_BACKOFF_MAX_MS", "100")),
        )



