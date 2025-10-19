from __future__ import annotations

# Backward-compatible shim for alert config validation entrypoint.
from .validators.base import ValidationResult
from .validators.alert_config_validator import (
    validate_alert_config,
    AlertConfigValidator,
)

__all__ = [
    "ValidationResult",
    "validate_alert_config",
    "AlertConfigValidator",
]


