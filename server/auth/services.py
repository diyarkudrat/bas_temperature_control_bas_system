"""Authentication services."""

import logging
import time
import json
import sqlite3
from typing import Optional
from .models import User, Session
from .exceptions import AuthError
from .role_service import RoleService

logger = logging.getLogger(__name__)


class AuditLogger:
    """Audit logging for authentication events."""
    
    def __init__(self, db_path: str, firestore_factory=None):
        self.db_path = db_path
        self.firestore_factory = firestore_factory
        self.firestore_audit = None
        
        # Initialize Firestore audit if available
        if firestore_factory and firestore_factory.is_audit_enabled():
            try:
                self.firestore_audit = firestore_factory.get_audit_service()
                logger.info("Initialized Firestore audit logger")
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore audit: {e}")
        
        logger.info(f"Initializing audit logger with database: {db_path}")
        self._init_tables()
    
    def _init_tables(self):
        """Initialize audit log tables."""
        logger.info("Initializing audit log tables")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                action TEXT NOT NULL,
                details TEXT DEFAULT '{}',
                success BOOLEAN NOT NULL,
                session_id TEXT
            )
        ''')
        
        # Create index for better query performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_log(timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_username 
            ON audit_log(username)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Audit log tables initialized successfully")
    
    def log_auth_success(self, username: str, ip_address: str, session_id: str):
        """Log successful authentication."""
        logger.info(f"Logging auth success for user: {username}")
        handled = False
        # Try Firestore first if available
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="LOGIN_SUCCESS",
                    username=username,
                    ip_address=ip_address,
                    details={"session_id": session_id, "ip_address": ip_address, "endpoint": "auth/login"}
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        
        # Fallback to SQLite if not handled above
        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="LOGIN_SUCCESS",
                session_id=session_id,
                success=True,
                details={"session_id": session_id, "ip_address": ip_address, "endpoint": "auth/login"}
            )
    
    def log_auth_failure(self, username: str, ip_address: str, reason: str):
        """Log failed authentication."""
        logger.warning(f"Logging auth failure for user: {username}, reason: {reason}")
        handled = False
        # Try Firestore first if available
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="LOGIN_FAILURE",
                    username=username,
                    ip_address=ip_address,
                    details={"failure_reason": reason, "attempted_at": __import__('datetime').datetime.utcnow().isoformat() + 'Z', "endpoint": "auth/login"}
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        
        # Fallback to SQLite
        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="LOGIN_FAILURE",
                success=False,
                details={"failure_reason": reason, "attempted_at": __import__('datetime').datetime.utcnow().isoformat() + 'Z', "endpoint": "auth/login"}
            )
    
    def log_session_access(self, session_id: str, endpoint: str):
        """Log session access."""
        logger.debug(f"Logging session access: {session_id[:12]}... to {endpoint}")
        self._log_event(
            session_id=session_id,
            action="SESSION_ACCESS",
            success=True,
            details={"session_id": session_id, "endpoint": endpoint}
        )
        
    def log_session_creation(self, username: str, ip_address: str, session_id: str):
        """Log session creation."""
        logger.info(f"Logging session creation for user: {username}")
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="SESSION_CREATED",
            session_id=session_id,
            success=True,
            details={"session_id": session_id}
        )
    
    def log_session_destruction(self, session_id: str, username: str = None):
        """Log session destruction."""
        logger.info(f"Logging session destruction: {session_id[:12]}...")
        self._log_event(
            username=username,
            session_id=session_id,
            action="SESSION_DESTROYED",
            success=True
        )
    
    def _log_event(self, **kwargs):
        """Log audit event."""
        logger.debug(f"Logging audit event: {kwargs.get('action', 'UNKNOWN')}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        from datetime import datetime
        # Store ISO-8601 UTC timestamp string to satisfy tests expecting ISO format
        now_iso = datetime.utcfromtimestamp(time.time()).isoformat() + 'Z'

        cursor.execute('''
            INSERT INTO audit_log (timestamp, username, ip_address, action, details, success, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            now_iso,
            kwargs.get('username'),
            kwargs.get('ip_address'),
            kwargs['action'],
            json.dumps(kwargs.get('details', {})),
            kwargs['success'],
            kwargs.get('session_id')
        ))
        
        conn.commit()
        conn.close()
        logger.debug("Audit event logged successfully")
    
    def log_permission_denied(self, username: str, user_id: str, ip_address: str, endpoint: str, reason: str):
        """Log permission denied event."""
        logger.warning(f"Logging permission denied for user: {username}, reason: {reason}")
        handled = False
        # Try Firestore first if available
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="PERMISSION_DENIED",
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    details={"endpoint": endpoint, "reason": reason}
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        
        # Fallback to SQLite
        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="PERMISSION_DENIED",
                endpoint=endpoint,
                success=False,
                details={"reason": reason}
            )
    
    def log_tenant_violation(self, user_id: str, username: str, ip_address: str, attempted_tenant: str, allowed_tenant: str):
        """Log tenant access violation."""
        logger.warning(f"Logging tenant violation for user: {username}")
        handled = False
        # Try Firestore first if available
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="TENANT_VIOLATION",
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    details={
                        "attempted_tenant": attempted_tenant,
                        "allowed_tenant": allowed_tenant
                    }
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        
        # Fallback to SQLite
        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="TENANT_VIOLATION",
                endpoint="tenant_access",
                success=False,
                details={
                    "attempted_tenant": attempted_tenant,
                    "allowed_tenant": allowed_tenant
                }
            )

class RateLimiter:
    """Rate limiting for authentication attempts."""
    
    def __init__(self, config, state_path: str | None = None):
        self.config = config
        self.attempts = {}  # {ip: {user: [timestamps]}}
        self.lockouts = {}  # {ip: lockout_until}
        # Only persist if explicitly configured via argument or env var
        import os
        env_path = os.getenv('BAS_RATE_LIMIT_STATE_PATH')
        self._state_path = state_path or env_path or None
        logger.info("Initializing rate limiter")
        self._load_state()
    
    def is_allowed(self, ip: str, username: str = None) -> tuple[bool, str]:
        """Check if request is allowed."""
        logger.debug(f"Checking rate limit for IP: {ip}, user: {username}")
        
        now = time.time()
        
        # Check IP lockout
        if ip in self.lockouts and now < self.lockouts[ip]:
            logger.warning(f"IP {ip} is locked until {self.lockouts[ip]}")
            return False, "IP temporarily locked"
        
        # Check rate limits
        if ip not in self.attempts:
            self.attempts[ip] = {}
        
        if username and username in self.attempts[ip]:
            attempts = self.attempts[ip][username]
            # Remove old attempts (older than 15 minutes)
            attempts = [t for t in attempts if now - t < 900]
            self.attempts[ip][username] = attempts
            
            if len(attempts) >= self.config.auth_attempts_per_15min:
                self.lockouts[ip] = now + 900  # 15 minute lockout
                logger.warning(f"IP {ip} locked due to too many attempts from user {username}")
                return False, "Too many failed attempts"
        
        logger.debug(f"Rate limit check passed for IP: {ip}")
        return True, "Allowed"
    
    def record_attempt(self, ip: str, username: str = None):
        """Record authentication attempt."""
        logger.debug(f"Recording attempt for IP: {ip}, user: {username}")
        
        now = time.time()
        
        if ip not in self.attempts:
            self.attempts[ip] = {}
        
        if username not in self.attempts[ip]:
            self.attempts[ip][username] = []
        
        self.attempts[ip][username].append(now)
        logger.debug(f"Attempt recorded for IP: {ip}, user: {username}")
        self._save_state()

    def clear_attempts(self, ip: str, username: str = None):
        """Clear attempt history for successful authentication."""
        logger.debug(f"Clearing attempts for IP: {ip}, user: {username}")
        
        if ip in self.attempts:
            if username and username in self.attempts[ip]:
                del self.attempts[ip][username]
                logger.debug(f"Cleared attempts for user {username} on IP {ip}")
            
            # If no users left for this IP, clear the IP entry
            if not self.attempts[ip]:
                del self.attempts[ip]
                logger.debug(f"Cleared all attempts for IP {ip}")
        self._save_state()
    
    def get_attempt_count(self, ip: str, username: str = None) -> int:
        """Get current attempt count for IP/user."""
        if ip not in self.attempts:
            return 0
        
        if username and username in self.attempts[ip]:
            return len(self.attempts[ip][username])
        
        return 0

    def _load_state(self):
        """Load attempts/lockouts from JSON if persistence enabled; ignore errors."""
        if not self._state_path:
            return
        try:
            with open(self._state_path, 'r') as f:
                data = json.load(f)
            self.attempts = data.get('attempts', {})
            self.lockouts = data.get('lockouts', {})
            logger.info("Rate limiter state loaded", extra={"path": self._state_path})
        except Exception as e:
            logger.debug(f"Rate limiter state not loaded: {e}")

    def _save_state(self):
        """Atomically persist attempts/lockouts to JSON if enabled; ignore errors."""
        if not self._state_path:
            return
        try:
            tmp_path = f"{self._state_path}.tmp"
            data = {
                'attempts': self.attempts,
                'lockouts': self.lockouts,
                'saved_at': time.time()
            }
            with open(tmp_path, 'w') as f:
                json.dump(data, f)
            # Atomic replace
            import os
            os.replace(tmp_path, self._state_path)
        except Exception as e:
            logger.debug(f"Rate limiter state not saved: {e}")