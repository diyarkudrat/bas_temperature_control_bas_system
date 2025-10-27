"""RoleService: secure role operations with rate limiting and monitoring."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)


def _roles_to_set(roles: List[str]) -> set[str]:
    return {str(r).strip().lower() for r in roles if isinstance(r, str) and r.strip()}


def _is_role_authorized(user_roles: List[str], required_role: str) -> bool:
    required = (required_role or "").strip().lower()
    if not required:
        return True
    have = _roles_to_set(user_roles)
    # Strict hierarchy: admin >= operator >= read-only
    if required == "read-only":
        return bool(have & {"read-only", "operator", "admin"})
    if required == "operator":
        return bool(have & {"operator", "admin"})
    if required == "admin":
        return "admin" in have
    # Unknown required role: deny by default
    return False


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

    # --------------------- Authorization Utilities ---------------------
    def is_authorized_for_path(
        self,
        user_roles: List[str],
        required_role: str,
        *,
        debug: bool = False,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Strict hierarchy authorization with optional debug info.

        Returns (authorized, debug_info?). When debug=True, debug_info contains
        normalized roles and the evaluated requirement for diagnostics.
        """
        ok = _is_role_authorized(user_roles, required_role)
        if not debug:
            return ok, None
        info = {
            "required": (required_role or "").strip().lower(),
            "normalized_roles": sorted(list(_roles_to_set(user_roles))),
            "authorized": ok,
        }
        return ok, info


