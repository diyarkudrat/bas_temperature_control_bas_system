"""Authentication module for BAS system."""

from .config import AuthConfig
from .models import User, Session, PendingMFA
from .managers import UserManager, SessionManager, MFAManager
from .middleware import require_auth, add_security_headers
from .services import SMSService, AuditLogger, RateLimiter
from .utils import hash_password, verify_password, create_session_fingerprint
from .exceptions import AuthError, SessionError, MFAError

__all__ = [
    'AuthConfig', 'User', 'Session', 'PendingMFA',
    'UserManager', 'SessionManager', 'MFAManager',
    'require_auth', 'add_security_headers',
    'SMSService', 'AuditLogger', 'RateLimiter',
    'hash_password', 'verify_password', 'create_session_fingerprint',
    'AuthError', 'SessionError', 'MFAError'
]
