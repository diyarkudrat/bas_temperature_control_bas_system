"""Authentication manager classes and orchestration."""

import sqlite3
import time
import threading
import logging
import json
from typing import Optional, List, Any, Mapping, Dict, Protocol, Tuple
from .models import User, Session
from .utils import hash_password, verify_password, generate_session_id, create_session_fingerprint
from .exceptions import AuthError, SessionError
from .circuit_breaker import CircuitBreaker
from server.config.breaker import BreakerConfig
from .revocation_service import RevocationService

logger = logging.getLogger(__name__)


class AuthProvider(Protocol):
    def verify_token(self, token: str) -> Mapping[str, Any]: ...
    def get_user_roles(self, uid: str) -> List[str]: ...


class RateLimiterLike(Protocol):
    def is_allowed(self, ip: str, username: Optional[str] = None) -> Tuple[bool, str]: ...
    def record_attempt(self, ip: str, username: Optional[str] = None) -> None: ...


class UserAuthManagerError(AuthError):
    """Base error for UserAuthManager orchestration failures."""


class RateLimitedError(UserAuthManagerError):
    pass


class TokenVerificationError(UserAuthManagerError):
    pass


class RevokedTokenError(UserAuthManagerError):
    pass


class UserAuthManager:
    """Coordinates provider verification, revocation checks, and rate limits.

    Dependencies are injected explicitly for testability and clarity.
    """

    def __init__(
        self,
        *,
        provider: AuthProvider,
        revocations: RevocationService,
        limiter: RateLimiterLike,
    ) -> None:
        self._provider = provider
        self._revocations = revocations
        self._limiter = limiter

    def verify_request_token(self, token: str, ip: str, username_hint: Optional[str] = None) -> Mapping[str, Any]:
        """End-to-end verification with rate limit and revocation enforcement.

        Raises RateLimitedError, TokenVerificationError, or RevokedTokenError.
        Returns verified claims on success.
        """
        allowed, _ = self._limiter.is_allowed(ip, username_hint)
        if not allowed:
            self._limiter.record_attempt(ip, username_hint)
            raise RateLimitedError("rate_limited")

        self._limiter.record_attempt(ip, username_hint)

        try:
            claims = self._provider.verify_token(token)
        except Exception as exc:  # noqa: BLE001 - caller expects wrapped errors
            raise TokenVerificationError(str(exc)) from exc

        jti = str(claims.get("jti", ""))
        if jti and self._revocations.is_revoked(jti):
            raise RevokedTokenError("token_revoked")

        return claims

class UserManager:
    """Manages user accounts and authentication."""
    
    def __init__(self, db_path: str, config, firestore_factory=None):
        self.db_path = db_path
        self.config = config
        self.firestore_factory = firestore_factory
        self.firestore_users = None
        # Optional external auth integrations (Auth0, etc.)
        self._roles_provider: Optional[Any] = None
        self._management_client: Optional[Any] = None
        # Circuit breaker for external roles provider
        try:
            breaker_cfg = getattr(getattr(config, 'breaker', None), '__class__', None)
            self._roles_breaker = CircuitBreaker(getattr(config, 'breaker', None))
        except Exception:
            self._roles_breaker = CircuitBreaker(BreakerConfig())
        
        # Initialize Firestore users service if available
        if firestore_factory and firestore_factory.is_auth_enabled():
            try:
                self.firestore_users = firestore_factory.get_users_service()
                logger.info("Initialized Firestore users service")
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore users service: {e}")
        
        logger.info(f"Initializing UserManager with database: {db_path}")
        self._init_tables()
    
    def _init_tables(self):
        """Initialize user tables."""
        logger.info("Initializing user tables")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
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
        ''')
        
        conn.commit()
        conn.close()
        logger.info("User tables initialized successfully")
    
    def create_user(self, username: str, password: str, 
                   role: str = "operator") -> User:
        """Create new user account."""
        logger.info(f"Creating user: {username} with role: {role}")
        
        # Validate password strength
        is_valid, message = self._validate_password_strength(password)
        if not is_valid:
            logger.warning(f"Password validation failed for user {username}: {message}")
            raise AuthError(f"Password validation failed: {message}")
        
        # Check if user exists
        if self.get_user(username):
            logger.warning(f"User {username} already exists")
            raise AuthError("User already exists")
        
        # Hash password
        password_hash, salt = hash_password(password)
        logger.debug(f"Password hashed for user {username}")
        
        # Create user
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            role=role
        )
        
        # Store in database
        self._store_user(user)
        logger.info(f"User {username} created successfully")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/password."""
        logger.info(f"Authenticating user: {username}")
        
        # Try Firestore first if available
        if self.firestore_users:
            try:
                result = self.firestore_users.get_by_username(username)
                if result.success and result.data:
                    user = result.data
                    logger.debug(f"User {username} found in Firestore")
                else:
                    logger.warning(f"User {username} not found in Firestore")
                    return None
            except Exception as e:
                logger.warning(f"Failed to authenticate via Firestore: {e}, falling back to SQLite")
                user = self.get_user(username)
                if not user:
                    logger.warning(f"User {username} not found")
                    return None
        else:
            # Use SQLite
            user = self.get_user(username)
            if not user:
                logger.warning(f"User {username} not found")
                return None
        
        # Check if account is locked
        if user.is_locked():
            logger.warning(f"Authentication attempt on locked account: {username}")
            return None
        
        # Verify password
        if verify_password(password, user.password_hash, user.salt):
            logger.info(f"User {username} authenticated successfully")
            # Reset failed attempts on successful login
            user.failed_attempts = 0
            user.locked_until = 0
            
            # Store updated user (Firestore or SQLite)
            if self.firestore_users:
                try:
                    self.firestore_users.update_user(user)
                    logger.debug(f"User {username} updated in Firestore")
                except Exception as e:
                    logger.warning(f"Failed to update user in Firestore: {e}")
                    self._store_user(user)  # Fallback to SQLite
            else:
                self._store_user(user)
            
            return user
        else:
            logger.warning(f"Authentication failed for user {username}")
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= self.config.max_login_attempts:
                user.locked_until = time.time() + self.config.lockout_duration
                logger.warning(f"Account {username} locked due to failed attempts")
            
            # Store updated user (Firestore or SQLite)
            if self.firestore_users:
                try:
                    self.firestore_users.update_user(user)
                    logger.debug(f"User {username} updated in Firestore")
                except Exception as e:
                    logger.warning(f"Failed to update user in Firestore: {e}")
                    self._store_user(user)  # Fallback to SQLite
            else:
                self._store_user(user)
            
            return None
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username."""
        logger.debug(f"Retrieving user: {username}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            data = dict(zip(columns, row))
            user = User.from_dict(data)
            logger.debug(f"User {username} retrieved successfully")
            return user
        
        logger.debug(f"User {username} not found")
        return None
    
    def update_last_login(self, username: str):
        """Update user's last login time."""
        logger.debug(f"Updating last login for user: {username}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE users SET last_login = ? WHERE username = ?',
            (time.time(), username)
        )
        
        conn.commit()
        conn.close()
        logger.debug(f"Last login updated for user {username}")
    
    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password strength."""
        from .utils import validate_password_strength
        return validate_password_strength(password)
    
    def _store_user(self, user: User):
        """Store user in database."""
        logger.debug(f"Storing user: {user.username}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users 
            (username, password_hash, salt, role, created_at, 
             last_login, failed_attempts, locked_until, password_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.username, user.password_hash, user.salt,
            user.role, user.created_at, user.last_login, user.failed_attempts,
            user.locked_until, json.dumps(user.password_history)
        ))
        
        conn.commit()
        conn.close()
        logger.debug(f"User {user.username} stored successfully")

    # ---------------------- External Roles Operations ----------------------
    def configure_roles_provider(self, provider: Any = None, management_client: Any = None) -> None:
        """Configure external roles provider and optional management client.

        The provider is expected to expose:
          - get_user_roles(user_id: str) -> List[str]
          - set_user_roles(user_id: str, roles: Mapping[str, Any], *, max_retries: int, initial_backoff_s: float, management_client: Any | None) -> Dict[str, Any]
        """
        self._roles_provider = provider
        self._management_client = management_client

    def get_effective_user_roles(self, username: str, user_id: Optional[str] = None) -> List[str]:
        """Return effective roles for a user.

        Preference order:
        1) External provider by user_id (if configured) with circuit breaker
        2) Local stored role in users table (single-role list) as bounded fallback
        """
        # Prefer external provider if available and breaker allows
        if self._roles_provider and user_id:
            if self._roles_breaker.allow_request():
                try:
                    roles = self._roles_provider.get_user_roles(user_id)
                    self._roles_breaker.record_success()
                    if isinstance(roles, list):
                        return [str(r) for r in roles]
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"get_effective_user_roles provider failure: {e}")
                    self._roles_breaker.record_failure()
            else:
                logger.debug("roles provider breaker open; skipping provider call")

        # Fallback to local single role
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
        """Set roles for a user in the external provider with retry wrappers.

        Delegates to the configured provider's set_user_roles. Allows per-call
        override of management_client. Raises ValueError on failure.
        """
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
    """Manages user sessions."""
    
    def __init__(self, db_path: str, config, firestore_factory=None):
        self.db_path = db_path
        self.config = config
        self.firestore_factory = firestore_factory
        self.firestore_sessions = None
        self.sessions = {}  # In-memory session cache
        self._cache_lock = threading.RLock()  # Thread-safe session cache
        
        # Initialize Firestore sessions service if available
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
        """Initialize session tables."""
        logger.info("Initializing session tables")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
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
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Session tables initialized successfully")
    
    def create_session(self, username: str, user_role: str, request) -> Session:
        """Create new session for user."""
        logger.info(f"Creating session for user: {username}")
        
        # Check concurrent session limits
        active_sessions = self._get_user_sessions(username)
        if len(active_sessions) >= self.config.max_concurrent_sessions:
            logger.warning(f"User {username} has reached concurrent session limit, removing oldest")
            # Remove oldest session
            oldest = min(active_sessions, key=lambda s: s.last_access)
            self.invalidate_session(oldest.session_id)
        
        # Generate session ID
        session_id = generate_session_id()
        
        # Create fingerprint
        fingerprint = create_session_fingerprint(
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.remote_addr
        )
        
        # Create session
        now = time.time()
        
        # Extract user_id and tenant_id safely (handle Mock objects in tests)
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
        
        # Store session (Firestore or SQLite)
        if self.firestore_sessions:
            try:
                # Create session in Firestore
                result = self.firestore_sessions.create_session(
                    user_id=session.user_id,
                    username=username,
                    role=user_role,
                    expires_in_seconds=self.config.session_timeout,
                    request_info={
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent', ''),
                        'tenant_id': session.tenant_id
                    }
                )
                if result:
                    logger.debug(f"Session created in Firestore for user {username}")
                else:
                    logger.warning(f"Failed to create session in Firestore, falling back to SQLite")
                    self._store_session(session)
            except Exception as e:
                logger.warning(f"Failed to create session in Firestore: {e}, falling back to SQLite")
                self._store_session(session)
        else:
            # Use SQLite
            self._store_session(session)
        
        # Update cache
        with self._cache_lock:
            self.sessions[session_id] = session
        
        logger.info(f"Session created for user {username}: {session_id[:12]}...")
        return session
    
    def validate_session(self, session_id: str, request) -> Optional[Session]:
        """Validate session and check fingerprint."""
        logger.debug(f"Validating session: {session_id[:12]}...")
        
        result: Optional[Session] = None
        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session not found: {session_id[:12]}...")
        else:
            # Check expiration
            if session.is_expired():
                logger.warning(f"Session expired: {session_id[:12]}...")
                self.invalidate_session(session_id)
            else:
                # Check fingerprint with input validation
                user_agent = request.headers.get('User-Agent', '')
                accept_language = request.headers.get('Accept-Language', '')
                accept_encoding = request.headers.get('Accept-Encoding', '')
                remote_addr = request.remote_addr or ''

                # Validate required fingerprint components
                if not user_agent or not remote_addr:
                    logger.warning(f"Insufficient fingerprint data for session: {session_id[:12]}...")
                    self.invalidate_session(session_id)
                else:
                    current_fingerprint = create_session_fingerprint(
                        user_agent, accept_language, accept_encoding, remote_addr
                    )

                    if session.fingerprint != current_fingerprint:
                        logger.warning(f"Session fingerprint mismatch: {session_id[:12]}...")
                        self.invalidate_session(session_id)
                    else:
                        logger.debug(f"Session validated successfully: {session_id[:12]}...")
                        result = session

        return result
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        result: Optional[Session] = None
        # Check cache first
        with self._cache_lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if session.is_expired():
                    logger.debug(f"Session expired in cache: {session_id[:12]}...")
                    del self.sessions[session_id]
                else:
                    result = session

        # Try Firestore first if available and not found
        if result is None and self.firestore_sessions:
            try:
                firestore_result = self.firestore_sessions.get_session(session_id)
                if firestore_result.success and firestore_result.data:
                    session = firestore_result.data
                    if not session.is_expired():
                        with self._cache_lock:
                            self.sessions[session_id] = session
                        logger.debug(f"Session loaded from Firestore: {session_id[:12]}...")
                        result = session
                    else:
                        logger.debug(f"Session expired in Firestore: {session_id[:12]}...")
                else:
                    logger.debug(f"Session not found in Firestore: {session_id[:12]}...")
            except Exception as e:
                logger.warning(f"Failed to get session from Firestore: {e}, falling back to SQLite")

        # Fallback to SQLite if still not found
        if result is None:
            logger.debug(f"Loading session from SQLite database: {session_id[:12]}...")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                columns = [desc[0] for desc in cursor.description]
                data = dict(zip(columns, row))
                session = Session.from_dict(data)
                if not session.is_expired():
                    with self._cache_lock:
                        self.sessions[session_id] = session
                    logger.debug(f"Session loaded from SQLite: {session_id[:12]}...")
                    result = session

        if result is None:
            logger.debug(f"Session not found: {session_id[:12]}...")
        return result
    
    def invalidate_session(self, session_id: str):
        """Invalidate session."""
        logger.info(f"Invalidating session: {session_id[:12]}...")
        
        # Remove from cache
        with self._cache_lock:
            self.sessions.pop(session_id, None)
        
        # Remove from Firestore if available
        if self.firestore_sessions:
            try:
                result = self.firestore_sessions.delete_session(session_id)
                if result.success:
                    logger.debug(f"Session invalidated in Firestore: {session_id[:12]}...")
                else:
                    logger.warning(f"Failed to invalidate session in Firestore: {result.error}")
            except Exception as e:
                logger.warning(f"Failed to invalidate session in Firestore: {e}")
        
        # Remove from SQLite (always do this as fallback)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Session invalidated: {session_id[:12]}...")
    
    def update_last_access(self, session_id: str):
        """Update session last access time."""
        logger.debug(f"Updating last access for session: {session_id[:12]}...")
        
        with self._cache_lock:
            if session_id in self.sessions:
                self.sessions[session_id].last_access = time.time()
        
        # Update in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE sessions SET last_access = ? WHERE session_id = ?',
            (time.time(), session_id)
        )
        
        conn.commit()
        conn.close()
    
    def _get_user_sessions(self, username: str) -> List[Session]:
        """Get all active sessions for a user."""
        logger.debug(f"Getting active sessions for user: {username}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT * FROM sessions WHERE username = ? AND expires_at > ?',
            (username, time.time())
        )
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            columns = [desc[0] for desc in cursor.description]
            data = dict(zip(columns, row))
            session = Session.from_dict(data)
            sessions.append(session)
        
        logger.debug(f"Found {len(sessions)} active sessions for user {username}")
        return sessions
    
    def _store_session(self, session: Session):
        """Store session in database."""
        logger.debug(f"Storing session: {session.session_id[:12]}...")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, username, role, created_at, expires_at, last_access, 
             fingerprint, ip_address, user_agent, user_id, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id, session.username, session.role, session.created_at,
            session.expires_at, session.last_access, session.fingerprint,
            session.ip_address, session.user_agent, session.user_id, session.tenant_id
        ))
        
        conn.commit()
        conn.close()
        logger.debug(f"Session stored: {session.session_id[:12]}...")
    
    def _start_cleanup_thread(self):
        """Start background thread to clean up expired sessions."""
        def cleanup_expired_sessions():
            while True:
                try:
                    logger.debug("Starting session cleanup")
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    # Remove expired sessions from database
                    cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (time.time(),))
                    deleted_count = cursor.rowcount
                    
                    # Remove expired sessions from cache
                    with self._cache_lock:
                        expired_sessions = [sid for sid, session in self.sessions.items() if session.is_expired()]
                        for sid in expired_sessions:
                            del self.sessions[sid]
                    
                    conn.commit()
                    conn.close()
                    
                    if deleted_count > 0 or expired_sessions:
                        logger.info(f"Cleaned up {deleted_count} expired sessions from database and {len(expired_sessions)} from cache")
                    
                except Exception as e:
                    logger.error(f"Error during session cleanup: {e}")
                
                # Run cleanup every 5 minutes
                time.sleep(300)
        
        cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
        cleanup_thread.start()
        logger.info("Session cleanup thread started")

