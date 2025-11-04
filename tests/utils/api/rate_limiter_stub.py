"""Rate limiter stub for API unit tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class RateLimitDecision:
    """Rate limit decision."""

    allowed: bool
    retry_after: float | None = None


class RateLimiterStub:
    """Simple stub capturing rate limit calls and returning configurable decisions."""

    def __init__(self) -> None:
        """Initialize rate limiter stub."""

        self.calls: list[Dict[str, Any]] = []
        self.default_decision = RateLimitDecision(allowed=True)

    def set_decision(self, *, allowed: bool, retry_after: float | None = None) -> None:
        """Set the decision."""

        self.default_decision = RateLimitDecision(allowed=allowed, retry_after=retry_after)

    def check(self, *args: Any, **kwargs: Any) -> RateLimitDecision:
        """Check the decision."""

        payload = {"args": args, "kwargs": kwargs}
        self.calls.append(payload)

        return self.default_decision

    def reset(self) -> None:
        """Reset the rate limiter stub."""
        
        self.calls.clear()
        self.default_decision = RateLimitDecision(allowed=True)

