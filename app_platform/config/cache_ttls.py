from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class CacheTTLs:
    """Centralized cache TTLs. Some are upper bounds; services may clamp by domain rules."""

    # Sessions: used as max TTL; services clamp to remaining expires_at
    session_max_seconds: int = 1800  # 30 minutes
    
    # Devices
    device_by_id_seconds: int = 60
    device_list_first_page_seconds: int = 60
    device_count_seconds: int = 30

    # Audit dashboard views
    audit_dashboard_seconds: int = 20

    # Auth metadata tiered TTLs
    auth_metadata_ttl_critical_seconds: int = 60
    auth_metadata_ttl_standard_seconds: int = 300

    @classmethod
    def from_env(cls) -> "CacheTTLs":
        """Load configuration from environment variables."""
        
        return cls(
            session_max_seconds=int(os.getenv("BAS_TTL_SESSION_MAX_S", "1800")),
            device_by_id_seconds=int(os.getenv("BAS_TTL_DEVICE_BY_ID_S", "60")),
            device_list_first_page_seconds=int(os.getenv("BAS_TTL_DEVICE_LIST_S", "60")),
            device_count_seconds=int(os.getenv("BAS_TTL_DEVICE_COUNT_S", "30")),
            audit_dashboard_seconds=int(os.getenv("BAS_TTL_AUDIT_DASHBOARD_S", "20")),
            auth_metadata_ttl_critical_seconds=int(os.getenv("BAS_TTL_AUTH_META_CRITICAL_S", "60")),
            auth_metadata_ttl_standard_seconds=int(os.getenv("BAS_TTL_AUTH_META_STANDARD_S", "300")),
        )



