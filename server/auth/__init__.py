"""Authentication module for BAS system."""

from .config import AuthConfig
from .models import User, Session
from .managers import UserManager, SessionManager, UserAuthManager, UserAuthManagerError, RateLimitedError, TokenVerificationError, RevokedTokenError
from .middleware import require_auth, add_security_headers
from .services import AuditLogger, RateLimiter
from .utils import hash_password, verify_password, create_session_fingerprint
from .exceptions import AuthError, SessionError

__all__ = [
    'AuthConfig', 'User', 'Session',
    'UserManager', 'SessionManager', 'UserAuthManager',
    'require_auth', 'add_security_headers',
    'AuditLogger', 'RateLimiter',
    'hash_password', 'verify_password', 'create_session_fingerprint',
    'AuthError', 'SessionError',
    'UserAuthManagerError', 'RateLimitedError', 'TokenVerificationError', 'RevokedTokenError'
]
