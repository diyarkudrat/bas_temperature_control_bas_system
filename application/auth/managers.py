"""Authentication managers (migrated)."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import Optional, List, Any, Mapping, Dict, Protocol, Tuple

from domains.auth.models import User, Session
from domains.auth.serializers import (
    session_from_dict,
    session_to_dict,
    user_from_dict,
    user_to_dict,
)
from domains.auth.exceptions import AuthError
from app_platform.utils.auth import (
    hash_password,
    verify_password,
    generate_session_id,
    create_session_fingerprint,
    validate_password_strength,
)
from app_platform.utils.circuit_breaker import CircuitBreaker
from app_platform.config.breaker import BreakerConfig


logger = logging.getLogger(__name__)


class AuthProvider(Protocol):
    """Protocol for an authentication provider."""
    
    def verify_token(self, token: str) -> Mapping[str, Any]: ...

    def get_user_roles(self, uid: str) -> List[str]: ...


class RateLimiterLike(Protocol):
    """Protocol for a rate limiter."""
    
    def is_allowed(self, ip: str, username: Optional[str] = None) -> Tuple[bool, str]: ...

    def record_attempt(self, ip: str, username: Optional[str] = None) -> None: ...


class UserAuthManagerError(AuthError):
    pass


class RateLimitedError(UserAuthManagerError):
    pass


class TokenVerificationError(UserAuthManagerError):
    pass


class RevokedTokenError(UserAuthManagerError):
    pass


class UserAuthManager:
    """Manage authentication requests and verify tokens."""

    def __init__(
        self,
        *,
        provider: AuthProvider,
        revocations: Any,
        limiter: RateLimiterLike,
    ) -> None:
        self._provider = provider
        self._revocations = revocations
        self._limiter = limiter

    def verify_request_token(self, token: str, ip: str, username_hint: Optional[str] = None) -> Mapping[str, Any]:
        """Verify a request token."""

        allowed, _ = self._limiter.is_allowed(ip, username_hint)

        if not allowed:
            self._limiter.record_attempt(ip, username_hint)
            raise RateLimitedError("rate_limited")

        self._limiter.record_attempt(ip, username_hint)

        try:
            claims = self._provider.verify_token(token)
        except Exception as exc:  # noqa: BLE001
            raise TokenVerificationError(str(exc)) from exc

        jti = str(claims.get("jti", ""))

        if jti and self._revocations.is_revoked(jti):
            raise RevokedTokenError("token_revoked")

        return claims


class UserManager:
    """Manage user accounts and credentials.

    Responsibilities:
    - Persist users in SQLite; optionally proxy to Firestore users service when enabled
    - Create users with password-strength enforcement and salted password hashing
    - Authenticate users; track failed attempts and apply lockout windows
    - Update last-login timestamp and persist user state changes
    - Provide role lookups with local fallback; integrates optional external roles provider

    Out of scope:
    - Session lifecycle (see SessionManager)
    - Token verification and rate limiting (see UserAuthManager)
    """

    def __init__(self, db_path: str, config, firestore_factory=None):
        """Initialize the UserManager."""

        self.db_path = db_path
        self.config = config
        self.firestore_factory = firestore_factory
        self.firestore_users = None
        self._roles_provider: Optional[Any] = None
        self._management_client: Optional[Any] = None

        try:
            self._roles_breaker = CircuitBreaker(getattr(config, 'breaker', None))
        except Exception:
            self._roles_breaker = CircuitBreaker(BreakerConfig())

        if firestore_factory and firestore_factory.is_auth_enabled():
            try:
                self.firestore_users = firestore_factory.get_users_service()
                logger.info("Initialized Firestore users service")
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore users service: {e}")

        logger.info(f"Initializing UserManager with database: {db_path}")

        self._init_tables()

    def _init_tables(self):
        """Initialize the users table in the SQLite database."""

        logger.info(f"Initializing users table in database: {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                created_at REAL NOT NULL,
                last_login REAL DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0,
                password_history TEXT DEFAULT '[]'
            )
            '''
        )
        conn.commit()
        conn.close()

    def create_user(self, username: str, password: str, role: str = "operator") -> User:
        """Create a new user account."""

        logger.info(f"Creating user: {username} with role: {role}")

        is_valid, message = self._validate_password_strength(password)

        if not is_valid:
            raise AuthError(f"Password validation failed: {message}")
        if self.get_user(username):
            raise AuthError("User already exists")
        password_hash, salt = hash_password(password)
        user = User(username=username, password_hash=password_hash, salt=salt, role=role)
        self._store_user(user)
        return user

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user."""

        if self.firestore_users:
            try:
                result = self.firestore_users.get_by_username(username)

                if result.success and result.data:
                    user = result.data
                else:
                    return None
            except Exception:
                user = self.get_user(username)
                if not user:
                    return None
        else:
            user = self.get_user(username)

            if not user:
                return None

        if user.is_locked():
            return None

        if verify_password(password, user.password_hash, user.salt):
            user.failed_attempts = 0
            user.locked_until = 0

            if self.firestore_users:
                try:
                    self.firestore_users.update_user(user)
                except Exception:
                    self._store_user(user)
            else:
                self._store_user(user)

            return user
        else:
            user.failed_attempts += 1

            if user.failed_attempts >= self.config.max_login_attempts:
                user.locked_until = time.time() + self.config.lockout_duration

            if self.firestore_users:
                try:
                    self.firestore_users.update_user(user)
                except Exception:
                    self._store_user(user)
            else:
                self._store_user(user)

            return None

    def get_user(self, username: str) -> Optional[User]:
        """Get a user by username."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            columns = [desc[0] for desc in cursor.description]
            data = dict(zip(columns, row))

            return user_from_dict(data)

        return None

    def update_last_login(self, username: str):
        """Update the last login timestamp for a user."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = ? WHERE username = ?', (time.time(), username))
        conn.commit()
        conn.close()

    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate the strength of a password."""

        return validate_password_strength(password)

    def _store_user(self, user: User):
        """Store a user in the SQLite database."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        record = user_to_dict(user)
        cursor.execute(
            '''
            INSERT OR REPLACE INTO users 
            (username, password_hash, salt, role, created_at, 
             last_login, failed_attempts, locked_until, password_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                record["username"],
                record["password_hash"],
                record["salt"],
                record["role"],
                record["created_at"],
                record["last_login"],
                record["failed_attempts"],
                record["locked_until"],
                record["password_history"],
            ),
        )
        conn.commit()
        conn.close()

    def configure_roles_provider(self, provider: Any = None, management_client: Any = None) -> None:
        """Configure the roles provider."""

        self._roles_provider = provider
        self._management_client = management_client

    def get_effective_user_roles(self, username: str, user_id: Optional[str] = None) -> List[str]:
        """Get the effective user roles."""

        if self._roles_provider and user_id:
            # For compatibility keep simple gate here; CircuitBreaker used elsewhere in provider
            try:
                roles = self._roles_provider.get_user_roles(user_id)
                if isinstance(roles, list):
                    return [str(r) for r in roles]
            except Exception as e:  # noqa: BLE001
                logger.warning(f"get_effective_user_roles provider failure: {e}")

        local = self.get_user(username)

        if local and isinstance(local.role, str) and local.role:
            return [local.role]

        return []

    def set_external_user_roles(
        self,
        user_id: str,
        roles: Mapping[str, Any],
        *,
        max_retries: int = 3,
        initial_backoff_s: float = 0.05,
        management_client: Any | None = None,
    ) -> Dict[str, Any]:
        """Set the external user roles."""

        if not self._roles_provider or not hasattr(self._roles_provider, "set_user_roles"):
            raise ValueError("roles provider not configured")

        client = management_client if management_client is not None else self._management_client
        try:
            return self._roles_provider.set_user_roles(
                user_id,
                roles,
                max_retries=max_retries,
                initial_backoff_s=initial_backoff_s,
                management_client=client,
            )
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"failed to set external roles: {e}") from e


class SessionManager:
    """Manage session lifecycle and authentication tokens."""

    def __init__(self, db_path: str, config, firestore_factory=None):
        """Initialize the SessionManager."""

        self.db_path = db_path
        self.config = config
        self.firestore_factory = firestore_factory
        self.firestore_sessions = None
        self.sessions = {}
        self._cache_lock = threading.RLock()

        if firestore_factory and firestore_factory.is_auth_enabled():
            try:
                self.firestore_sessions = firestore_factory.get_sessions_service()
                logger.info("Initialized Firestore sessions service")
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore sessions service: {e}")

        logger.info(f"Initializing SessionManager with database: {db_path}")

        self._init_tables()
        self._start_cleanup_thread()

    def _init_tables(self):
        """Initialize the sessions table in the SQLite database."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                last_access REAL NOT NULL,
                fingerprint TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                user_id TEXT DEFAULT 'unknown',
                tenant_id TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )
            '''
        )
        conn.commit()
        conn.close()

    def create_session(self, username: str, user_role: str, request) -> Session:
        """Create a new session."""

        active_sessions = self._get_user_sessions(username)

        if len(active_sessions) >= self.config.max_concurrent_sessions:
            oldest = min(active_sessions, key=lambda s: s.last_access)
            self.invalidate_session(oldest.session_id)

        session_id = generate_session_id()

        fingerprint = create_session_fingerprint(
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.remote_addr,
        )

        now = time.time()
        user_id = 'unknown'
        tenant_id = None

        if hasattr(request, 'user_id') and not hasattr(request.user_id, '_mock_name'):
            user_id = request.user_id
        if hasattr(request, 'tenant_id') and not hasattr(request.tenant_id, '_mock_name'):
            tenant_id = request.tenant_id

        session = Session(
            session_id=session_id,
            username=username,
            role=user_role,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=now,
            expires_at=now + self.config.session_timeout,
            last_access=now,
            fingerprint=fingerprint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
        )

        if self.firestore_sessions:
            try:
                result = self.firestore_sessions.create_session(
                    user_id=session.user_id,
                    username=username,
                    role=user_role,
                    expires_in_seconds=self.config.session_timeout,
                    request_info={'ip_address': request.remote_addr, 'user_agent': request.headers.get('User-Agent', ''), 'tenant_id': session.tenant_id},
                )

                if not result:
                    self._store_session(session)
            except Exception:
                self._store_session(session)
        else:
            self._store_session(session)

        with self._cache_lock:
            self.sessions[session_id] = session

        return session

    def validate_session(self, session_id: str, request) -> Optional[Session]:
        """Validate a session."""

        result: Optional[Session] = None

        session = self.get_session(session_id)

        if not session:
            return None

        if session.is_expired():
            self.invalidate_session(session_id)
            return None

        user_agent = request.headers.get('User-Agent', '')
        accept_language = request.headers.get('Accept-Language', '')
        accept_encoding = request.headers.get('Accept-Encoding', '')
        remote_addr = request.remote_addr or ''

        if not user_agent or not remote_addr:
            self.invalidate_session(session_id)
            return None

        current_fingerprint = create_session_fingerprint(user_agent, accept_language, accept_encoding, remote_addr)

        if session.fingerprint != current_fingerprint:
            self.invalidate_session(session_id)
            return None

        result = session
        return result

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by session ID."""

        result: Optional[Session] = None
        
        with self._cache_lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]

                if session.is_expired():
                    del self.sessions[session_id]
                else:
                    result = session

        if result is None and self.firestore_sessions:
            try:
                firestore_result = self.firestore_sessions.get_session(session_id)

                if firestore_result.success and firestore_result.data:
                    session = firestore_result.data

                    if not session.is_expired():
                        with self._cache_lock:
                            self.sessions[session_id] = session

                        result = session
            except Exception:
                pass

        if result is None:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                columns = [desc[0] for desc in cursor.description]
                data = dict(zip(columns, row))
                session = session_from_dict(data)

                if not session.is_expired():
                    with self._cache_lock:
                        self.sessions[session_id] = session

                    result = session

        return result

    def invalidate_session(self, session_id: str):
        """Invalidate a session."""

        with self._cache_lock:
            self.sessions.pop(session_id, None)

        if self.firestore_sessions:
            try:
                self.firestore_sessions.delete_session(session_id)
            except Exception:
                pass

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()

    def update_last_access(self, session_id: str):
        """Update the last access timestamp for a session."""

        with self._cache_lock:
            if session_id in self.sessions:
                self.sessions[session_id].last_access = time.time()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE sessions SET last_access = ? WHERE session_id = ?', (time.time(), session_id))
        conn.commit()
        conn.close()

    def _get_user_sessions(self, username: str) -> List[Session]:
        """Get the active sessions for a user."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sessions WHERE username = ? AND expires_at > ?', (username, time.time()))
        rows = cursor.fetchall()
        conn.close()
        sessions: List[Session] = []

        for row in rows:
            columns = [desc[0] for desc in cursor.description]
            data = dict(zip(columns, row))
            session = session_from_dict(data)
            sessions.append(session)

        return sessions

    def _store_session(self, session: Session):
        """Store a session in the SQLite database."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        record = session_to_dict(session)
        cursor.execute(
            '''
            INSERT OR REPLACE INTO sessions 
            (session_id, username, role, created_at, expires_at, last_access, 
             fingerprint, ip_address, user_agent, user_id, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                record["session_id"],
                record["username"],
                record["role"],
                record["created_at"],
                record["expires_at"],
                record["last_access"],
                record["fingerprint"],
                record["ip_address"],
                record["user_agent"],
                record["user_id"],
                record["tenant_id"],
            ),
        )
        conn.commit()
        conn.close()

    def _start_cleanup_thread(self):
        """Start the cleanup thread for expired sessions."""

        def cleanup_expired_sessions():
            while True:
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (time.time(),))
                    with self._cache_lock:
                        expired_sessions = [sid for sid, session in self.sessions.items() if session.is_expired()]
                        for sid in expired_sessions:
                            del self.sessions[sid]
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

                time.sleep(300)
                
        t = threading.Thread(target=cleanup_expired_sessions, daemon=True)
        t.start()


