"""Server configuration loader with emulator support."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    """Top-level server configuration used by services."""

    use_emulators: bool = False
    emulator_redis_url: Optional[str] = None
    firestore_emulator_host: Optional[str] = None
    gcp_project_id: Optional[str] = None

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
        return cls(
            use_emulators=use_emulators,
            emulator_redis_url=os.getenv("EMULATOR_REDIS_URL"),
            firestore_emulator_host=os.getenv("FIRESTORE_EMULATOR_HOST"),
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
        )


def get_server_config() -> ServerConfig:
    """Convenience accessor for callers that do not manage config lifecycle."""
    return ServerConfig.from_env()


