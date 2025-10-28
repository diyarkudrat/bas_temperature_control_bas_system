import logging
from typing import Optional

from application.auth.managers import UserManager, SessionManager
from application.auth.services import AuditLogger, RateLimiter

logger = logging.getLogger(__name__)


class LoginUser:
    def __init__(self, users: UserManager, sessions: SessionManager, audit: AuditLogger, limiter: RateLimiter):
        self.users = users
        self.sessions = sessions
        self.audit = audit
        self.limiter = limiter

    def execute(self, username: str, password: str, request) -> Optional[str]:
        ip = getattr(request, 'remote_addr', '')
        allowed, _ = self.limiter.is_allowed(ip, username)
        if not allowed:
            self.limiter.record_attempt(ip, username)
            self.audit.log_auth_failure(username, ip, reason="rate_limited")
            return None

        self.limiter.record_attempt(ip, username)
        user = self.users.authenticate_user(username, password)
        if not user:
            self.audit.log_auth_failure(username, ip, reason="invalid_credentials")
            return None

        sess = self.sessions.create_session(username, user.role, request)
        self.audit.log_auth_success(username, ip, session_id=sess.session_id)
        self.limiter.clear_attempts(ip, username)
        return sess.session_id


class Logout:
    def __init__(self, sessions: SessionManager, audit: AuditLogger):
        self.sessions = sessions
        self.audit = audit

    def execute(self, session_id: str, username: Optional[str] = None) -> bool:
        try:
            self.sessions.invalidate_session(session_id)
            self.audit.log_session_destruction(session_id, username=username)
            return True
        except Exception as e:
            logger.warning(f"logout failed: {e}")
            return False


class RotateSession:
    def __init__(self, sessions: SessionManager, audit: AuditLogger):
        self.sessions = sessions
        self.audit = audit

    def execute(self, old_session_id: str, request) -> Optional[str]:
        old = self.sessions.get_session(old_session_id)
        if not old:
            return None
        self.sessions.invalidate_session(old_session_id)
        new_session = self.sessions.create_session(old.username, old.role, request)
        self.audit.log_session_creation(old.username, getattr(request, 'remote_addr', ''), new_session.session_id)
        return new_session.session_id
