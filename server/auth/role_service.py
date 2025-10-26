"""RoleService: secure role operations with rate limiting and monitoring."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)


class RoleService:
    """Secure role operations with rate limiting and basic monitoring.

    This service provides a thin wrapper around external role management
    (configured on UserManager) and enforces per-IP/user request limits to
    mitigate brute-force or abusive usage of role endpoints.
    """

    def __init__(self, user_manager: Any, audit_logger: Optional[Any], rate_limiter: Any):
        self.user_manager = user_manager
        self.audit_logger = audit_logger
        self.rate_limiter = rate_limiter

    def _rate_check(self, ip: str, username: Optional[str]) -> Tuple[bool, str]:
        try:
            return self.rate_limiter.is_allowed(ip, username)
        except Exception as e:  # Defensive: do not block on limiter errors
            logger.warning(f"rate limiter error: {e}")
            return True, "Allowed"

    def get_roles(self, requester_username: str, requester_ip: str, target_user_id: str) -> list[str]:
        allowed, _ = self._rate_check(requester_ip, requester_username)
        if not allowed:
            if self.audit_logger:
                try:
                    self.audit_logger.log_permission_denied(
                        username=requester_username,
                        user_id=target_user_id,
                        ip_address=requester_ip,
                        endpoint="roles:get",
                        reason="rate_limited",
                    )
                except Exception:
                    pass
            # Record attempt even when blocked
            self.rate_limiter.record_attempt(requester_ip, requester_username)
            return []

        # Count every request for monitoring/limits
        self.rate_limiter.record_attempt(requester_ip, requester_username)
        try:
            # username not strictly needed here; user_id is the external identifier
            return self.user_manager.get_effective_user_roles(requester_username, user_id=target_user_id)
        except Exception as e:
            logger.warning(f"get_roles failed: {e}")
            return []

    def set_roles(
        self,
        requester_username: str,
        requester_ip: str,
        target_user_id: str,
        roles: Mapping[str, Any],
        *,
        max_retries: int = 3,
        initial_backoff_s: float = 0.05,
    ) -> dict:
        allowed, _ = self._rate_check(requester_ip, requester_username)
        if not allowed:
            if self.audit_logger:
                try:
                    self.audit_logger.log_permission_denied(
                        username=requester_username,
                        user_id=target_user_id,
                        ip_address=requester_ip,
                        endpoint="roles:set",
                        reason="rate_limited",
                    )
                except Exception:
                    pass
            # Record attempt even when blocked
            self.rate_limiter.record_attempt(requester_ip, requester_username)
            return {"success": False, "error": "rate_limited"}

        # Count every request for monitoring/limits
        self.rate_limiter.record_attempt(requester_ip, requester_username)

        try:
            out = self.user_manager.set_external_user_roles(
                target_user_id,
                roles,
                max_retries=max_retries,
                initial_backoff_s=initial_backoff_s,
            )
            return {"success": True, "result": out}
        except Exception as e:
            logger.warning(f"set_roles failed: {e}")
            return {"success": False, "error": str(e)}


