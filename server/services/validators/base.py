from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol


@dataclass(frozen=True)
class ValidationResult:
    success: bool
    errors: List[str]
    warnings: List[str]
    normalized: Optional[Dict[str, Any]] = None


class Validator(Protocol):
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        ...


