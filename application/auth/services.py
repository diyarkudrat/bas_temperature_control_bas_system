"""Authentication services."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import os as _os


logger = logging.getLogger(__name__)


class AuditLogger:
    """Audit logging for authentication events."""

    def __init__(self, db_path: str, firestore_factory=None):
        """Initialize the AuditLogger."""

        self.db_path = db_path
        self.firestore_factory = firestore_factory
        self.firestore_audit = None
        if firestore_factory and firestore_factory.is_audit_enabled():
            try:
                self.firestore_audit = firestore_factory.get_audit_service()
                logger.info("Initialized Firestore audit logger")
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore audit: {e}")
        logger.info(f"Initializing audit logger with database: {db_path}")
        self._init_tables()

    def _init_tables(self):
        """Initialize the audit log table in the SQLite database."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
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
            '''
        )
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)')
        conn.commit()
        conn.close()

    def log_auth_success(self, username: str, ip_address: str, session_id: str):
        """Log a successful authentication attempt."""

        handled = False

        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="LOGIN_SUCCESS",
                    username=username,
                    ip_address=ip_address,
                    details={"session_id": session_id, "ip_address": ip_address, "endpoint": "auth/login"},
                )

                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")

        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="LOGIN_SUCCESS",
                session_id=session_id,
                success=True,
                details={"session_id": session_id, "ip_address": ip_address, "endpoint": "auth/login"},
            )

    def log_auth_failure(self, username: str, ip_address: str, reason: str):
        """Log a failed authentication attempt."""

        handled = False

        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="LOGIN_FAILURE",
                    username=username,
                    ip_address=ip_address,
                    details={"failure_reason": reason, "attempted_at": __import__('datetime').datetime.utcnow().isoformat() + 'Z', "endpoint": "auth/login"},
                )

                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")

        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="LOGIN_FAILURE",
                success=False,
                details={"failure_reason": reason, "attempted_at": __import__('datetime').datetime.utcnow().isoformat() + 'Z', "endpoint": "auth/login"},
            )

    def log_session_access(self, session_id: str, endpoint: str):
        """Log a session access attempt."""

        self._log_event(session_id=session_id, action="SESSION_ACCESS", success=True, details={"session_id": session_id, "endpoint": endpoint})

    def log_session_creation(self, username: str, ip_address: str, session_id: str):
        """Log a session creation attempt."""

        self._log_event(username=username, ip_address=ip_address, action="SESSION_CREATED", session_id=session_id, success=True, details={"session_id": session_id})

    def log_session_destruction(self, session_id: str, username: str = None):
        """Log a session destruction attempt."""

        self._log_event(username=username, session_id=session_id, action="SESSION_DESTROYED", success=True)

    def _log_event(self, **kwargs):
        """Log an audit event."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        from datetime import datetime
        now_iso = datetime.utcfromtimestamp(time.time()).isoformat() + 'Z'
        cursor.execute(
            '''
            INSERT INTO audit_log (timestamp, username, ip_address, action, details, success, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                now_iso,
                kwargs.get('username'),
                kwargs.get('ip_address'),
                kwargs.get('action'),
                json.dumps(kwargs.get('details', {})),
                kwargs.get('success'),
                kwargs.get('session_id'),
            ),
        )
        conn.commit()
        conn.close()

    def log_permission_denied(self, username: str, user_id: str, ip_address: str, endpoint: str, reason: str):
        """Log a permission denied attempt."""

        handled = False
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="PERMISSION_DENIED",
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    details={"endpoint": endpoint, "reason": reason},
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        if not handled:
            self._log_event(username=username, ip_address=ip_address, action="PERMISSION_DENIED", endpoint=endpoint, success=False, details={"reason": reason})

    def log_tenant_violation(self, user_id: str, username: str, ip_address: str, attempted_tenant: str, allowed_tenant: str):
        """Log a tenant violation attempt."""

        handled = False
        if self.firestore_audit:
            try:
                self.firestore_audit.log_event(
                    event_type="TENANT_VIOLATION",
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    details={"attempted_tenant": attempted_tenant, "allowed_tenant": allowed_tenant},
                )
                handled = True
            except Exception as e:
                logger.warning(f"Failed to log to Firestore: {e}")
        if not handled:
            self._log_event(
                username=username,
                ip_address=ip_address,
                action="TENANT_VIOLATION",
                endpoint="tenant_access",
                success=False,
                details={"attempted_tenant": attempted_tenant, "allowed_tenant": allowed_tenant},
            )


class RateLimiter:
    """Rate limiting for authentication attempts."""

    def __init__(self, config, state_path: str | None = None):
        """Initialize the RateLimiter."""

        self.config = config
        self.attempts = {}
        self.lockouts = {}
        import os as _os
        env_path = _os.getenv('BAS_RATE_LIMIT_STATE_PATH')
        self._state_path = state_path or env_path or None
        logger.info("Initializing rate limiter")
        self._load_state()

    def is_allowed(self, ip: str, username: str = None) -> tuple[bool, str]:
        """Check if an authentication attempt is allowed."""

        now = time.time()

        if ip in self.lockouts and now < self.lockouts[ip]:
            return False, "IP temporarily locked"

        if ip not in self.attempts:
            self.attempts[ip] = {}

        if username and username in self.attempts[ip]:
            attempts = [t for t in self.attempts[ip][username] if now - t < 900]

            self.attempts[ip][username] = attempts

            if len(attempts) >= self.config.auth_attempts_per_15min:
                self.lockouts[ip] = now + 900

                return False, "Too many failed attempts"

        return True, "Allowed"

    def record_attempt(self, ip: str, username: str = None):
        """Record an authentication attempt."""

        now = time.time()

        if ip not in self.attempts:
            self.attempts[ip] = {}

        if username not in self.attempts[ip]:
            self.attempts[ip][username] = []

        self.attempts[ip][username].append(now)
        self._save_state()

    def clear_attempts(self, ip: str, username: str = None):
        """Clear authentication attempts."""

        if ip in self.attempts:
            if username and username in self.attempts[ip]:
                del self.attempts[ip][username]

            if not self.attempts[ip]:
                del self.attempts[ip]

        self._save_state()

    def get_attempt_count(self, ip: str, username: str = None) -> int:
        """Get the number of authentication attempts."""

        if ip not in self.attempts:
            return 0

        if username and username in self.attempts[ip]:
            return len(self.attempts[ip][username])

        return 0

    def _load_state(self):
        """Load the rate limiting state from the file system."""

        if not self._state_path:
            return

        try:
            with open(self._state_path, 'r') as f:
                data = json.load(f)

            self.attempts = data.get('attempts', {})
            self.lockouts = data.get('lockouts', {})
        except Exception:
            pass

    def _save_state(self):
        """Save the rate limiting state to the file system."""

        if not self._state_path:
            return

        try:
            tmp_path = f"{self._state_path}.tmp"
            data = {'attempts': self.attempts, 'lockouts': self.lockouts, 'saved_at': time.time()}

            with open(tmp_path, 'w') as f:
                json.dump(data, f)
            
            _os.replace(tmp_path, self._state_path)
        except Exception:
            pass


