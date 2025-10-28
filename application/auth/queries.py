from typing import Optional, Tuple, Dict, Any, List

from application.auth.managers import SessionManager, UserManager
from domains.auth.services import RoleService


class GetSessionStatus:
    def __init__(self, sessions: SessionManager):
        self.sessions = sessions

    def execute(self, session_id: str, request) -> Optional[Dict[str, Any]]:
        sess = self.sessions.validate_session(session_id, request)
        if not sess:
            return None
        return {
            "session_id": sess.session_id,
            "username": sess.username,
            "role": sess.role,
            "expires_at": sess.expires_at,
            "last_access": sess.last_access,
            "user_id": sess.user_id,
            "tenant_id": sess.tenant_id,
        }


class AuthorizeRoles:
    def __init__(self, users: UserManager, role_service: RoleService):
        self.users = users
        self.role_service = role_service

    def execute(self, requester_username: str, requester_ip: str, target_user_id: str, required_role: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        roles = self.role_service.get_roles(requester_username, requester_ip, target_user_id)
        ok, info = self.role_service.is_authorized_for_path(roles, required_role, debug=True)
        return ok, info
