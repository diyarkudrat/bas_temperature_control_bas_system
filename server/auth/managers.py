"""Authentication manager classes."""

import sqlite3
import time
import threading
import logging
import json
from typing import Optional, List
from .models import User, Session, PendingMFA
from .utils import hash_password, verify_password, generate_session_id, generate_mfa_code, create_session_fingerprint
from .exceptions import AuthError, SessionError, MFAError

logger = logging.getLogger(__name__)

class UserManager:
    """Manages user accounts and authentication."""
    
    def __init__(self, db_path: str, config):
        self.db_path = db_path
        self.config = config
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
                phone_number TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                created_at REAL NOT NULL,
                last_login REAL DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0,
                password_history TEXT DEFAULT '[]',
                mfa_enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("User tables initialized successfully")
    
    def create_user(self, username: str, password: str, phone_number: str, 
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
            phone_number=phone_number,
            role=role
        )
        
        # Store in database
        self._store_user(user)
        logger.info(f"User {username} created successfully")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username/password."""
        logger.info(f"Authenticating user: {username}")
        
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
            self._store_user(user)
            return user
        else:
            logger.warning(f"Authentication failed for user {username}")
            # Increment failed attempts
            user.failed_attempts += 1
            if user.failed_attempts >= self.config.max_login_attempts:
                user.locked_until = time.time() + self.config.lockout_duration
                logger.warning(f"Account {username} locked due to failed attempts")
            
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
            (username, password_hash, salt, phone_number, role, created_at, 
             last_login, failed_attempts, locked_until, password_history, mfa_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.username, user.password_hash, user.salt, user.phone_number,
            user.role, user.created_at, user.last_login, user.failed_attempts,
            user.locked_until, json.dumps(user.password_history), user.mfa_enabled
        ))
        
        conn.commit()
        conn.close()
        logger.debug(f"User {user.username} stored successfully")

class SessionManager:
    """Manages user sessions."""
    
    def __init__(self, db_path: str, config):
        self.db_path = db_path
        self.config = config
        self.sessions = {}  # In-memory session cache
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
                mfa_verified BOOLEAN DEFAULT 1,
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
        session = Session(
            session_id=session_id,
            username=username,
            role=user_role,
            created_at=now,
            expires_at=now + self.config.session_timeout,
            last_access=now,
            fingerprint=fingerprint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            mfa_verified=True
        )
        
        # Store session
        self._store_session(session)
        self.sessions[session_id] = session
        
        logger.info(f"Session created for user {username}: {session_id[:12]}...")
        return session
    
    def validate_session(self, session_id: str, request) -> Optional[Session]:
        """Validate session and check fingerprint."""
        logger.debug(f"Validating session: {session_id[:12]}...")
        
        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session not found: {session_id[:12]}...")
            return None
        
        # Check expiration
        if session.is_expired():
            logger.warning(f"Session expired: {session_id[:12]}...")
            self.invalidate_session(session_id)
            return None
        
        # Check fingerprint
        current_fingerprint = create_session_fingerprint(
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.remote_addr
        )
        
        if session.fingerprint != current_fingerprint:
            logger.warning(f"Session fingerprint mismatch: {session_id[:12]}...")
            self.invalidate_session(session_id)
            return None
        
        logger.debug(f"Session validated successfully: {session_id[:12]}...")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        # Check cache first
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if session.is_expired():
                logger.debug(f"Session expired in cache: {session_id[:12]}...")
                del self.sessions[session_id]
                return None
            return session
        
        # Load from database
        logger.debug(f"Loading session from database: {session_id[:12]}...")
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
                self.sessions[session_id] = session
                logger.debug(f"Session loaded from database: {session_id[:12]}...")
                return session
        
        logger.debug(f"Session not found in database: {session_id[:12]}...")
        return None
    
    def invalidate_session(self, session_id: str):
        """Invalidate session."""
        logger.info(f"Invalidating session: {session_id[:12]}...")
        
        # Remove from cache
        self.sessions.pop(session_id, None)
        
        # Remove from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Session invalidated: {session_id[:12]}...")
    
    def update_last_access(self, session_id: str):
        """Update session last access time."""
        logger.debug(f"Updating last access for session: {session_id[:12]}...")
        
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
             fingerprint, ip_address, user_agent, mfa_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id, session.username, session.role, session.created_at,
            session.expires_at, session.last_access, session.fingerprint,
            session.ip_address, session.user_agent, session.mfa_verified
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

class MFAManager:
    """Manages MFA codes and verification."""
    
    def __init__(self, config):
        self.config = config
        self.pending_mfa = {}  # In-memory storage
        logger.info("Initializing MFAManager")
    
    def generate_code(self, username: str) -> str:
        """Generate MFA code for user."""
        logger.info(f"Generating MFA code for user: {username}")
        
        code = generate_mfa_code(self.config.mfa_code_length)
        
        # Store pending MFA
        now = time.time()
        pending = PendingMFA(
            username=username,
            code=code,
            phone_number="",  # Will be set by SMS service
            created_at=now,
            expires_at=now + self.config.mfa_code_expiry
        )
        
        self.pending_mfa[username] = pending
        logger.info(f"MFA code generated for user {username}, expires in {self.config.mfa_code_expiry}s")
        return code
    
    def verify_code(self, username: str, code: str) -> bool:
        """Verify MFA code."""
        logger.info(f"Verifying MFA code for user: {username}")
        
        if username not in self.pending_mfa:
            logger.warning(f"No pending MFA found for user: {username}")
            return False
        
        pending = self.pending_mfa[username]
        
        # Check expiration
        if pending.is_expired():
            logger.warning(f"MFA code expired for user: {username}")
            del self.pending_mfa[username]
            return False
        
        # Verify code (constant-time comparison)
        import secrets
        is_valid = secrets.compare_digest(pending.code, code)
        
        if is_valid:
            logger.info(f"MFA code verified successfully for user: {username}")
            del self.pending_mfa[username]
        else:
            logger.warning(f"MFA code verification failed for user: {username}")
        
        return is_valid
    
    def get_pending(self, username: str) -> Optional[PendingMFA]:
        """Get pending MFA for user."""
        logger.debug(f"Getting pending MFA for user: {username}")
        return self.pending_mfa.get(username)
    
    def clear_pending(self, username: str):
        """Clear pending MFA for user."""
        logger.debug(f"Clearing pending MFA for user: {username}")
        self.pending_mfa.pop(username, None)
