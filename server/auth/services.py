"""Authentication services."""

import logging
import time
import json
import sqlite3
from typing import Optional
from .models import User, Session
from .exceptions import AuthError

logger = logging.getLogger(__name__)

class SMSService:
    """SMS service for MFA delivery."""
    
    def __init__(self, config):
        self.config = config
        self.client = None
        logger.info("Initializing SMS service")
        
        if config.twilio_account_sid and config.twilio_auth_token:
            try:
                from twilio.rest import Client
                self.client = Client(config.twilio_account_sid, config.twilio_auth_token)
                logger.info("SMS service initialized with Twilio")
            except ImportError:
                logger.error("Twilio library not installed")
            except Exception as e:
                logger.error(f"Failed to initialize Twilio client: {e}")
        else:
            logger.warning("SMS service not configured - Twilio credentials missing")
    
    def send_mfa_code(self, phone_number: str, code: str) -> bool:
        """Send MFA code via SMS."""
        logger.info(f"Sending MFA code to {phone_number[:3]}***{phone_number[-4:]}")
        
        # Test mode: if no Twilio client, simulate successful SMS
        if not self.client:
            logger.warning("SMS service not configured - running in test mode")
            logger.info(f"TEST MODE: MFA code for {phone_number} is: {code}")
            logger.info("In production, configure Twilio credentials in config/secrets.json")
            return True
        
        try:
            message = self.client.messages.create(
                body=f"Your BAS authentication code is: {code}. This code expires in {self.config.mfa_code_expiry // 60} minutes.",
                from_=self.config.twilio_from_number,
                to=phone_number
            )
            
            logger.info(f"SMS sent successfully: {message.sid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send SMS to {phone_number[:3]}***{phone_number[-4:]}: {e}")
            return False

class AuditLogger:
    """Audit logging for authentication events."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
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
                timestamp REAL NOT NULL,
                username TEXT,
                ip_address TEXT,
                action TEXT NOT NULL,
                endpoint TEXT,
                success BOOLEAN NOT NULL,
                details TEXT DEFAULT '{}'
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
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="LOGIN_SUCCESS",
            endpoint="auth/login",
            success=True,
            details={"session_id": session_id}
        )
    
    def log_auth_failure(self, username: str, ip_address: str, reason: str):
        """Log failed authentication."""
        logger.warning(f"Logging auth failure for user: {username}, reason: {reason}")
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="LOGIN_FAILURE",
            endpoint="auth/login",
            success=False,
            details={"reason": reason}
        )
    
    def log_session_access(self, session_id: str, endpoint: str):
        """Log session access."""
        logger.debug(f"Logging session access: {session_id[:12]}... to {endpoint}")
        self._log_event(
            session_id=session_id,
            action="SESSION_ACCESS",
            endpoint=endpoint,
            success=True
        )
    
    def log_mfa_success(self, username: str, ip_address: str):
        """Log successful MFA verification."""
        logger.info(f"Logging MFA success for user: {username}")
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="MFA_SUCCESS",
            endpoint="auth/verify",
            success=True
        )
    
    def log_mfa_failure(self, username: str, ip_address: str, reason: str):
        """Log failed MFA verification."""
        logger.warning(f"Logging MFA failure for user: {username}, reason: {reason}")
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="MFA_FAILURE",
            endpoint="auth/verify",
            success=False,
            details={"reason": reason}
        )
    
    def log_session_creation(self, username: str, ip_address: str, session_id: str):
        """Log session creation."""
        logger.info(f"Logging session creation for user: {username}")
        self._log_event(
            username=username,
            ip_address=ip_address,
            action="SESSION_CREATED",
            endpoint="auth/verify",
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
            endpoint="auth/logout",
            success=True
        )
    
    def _log_event(self, **kwargs):
        """Log audit event."""
        logger.debug(f"Logging audit event: {kwargs.get('action', 'UNKNOWN')}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, username, ip_address, action, endpoint, success, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            time.time(),
            kwargs.get('username'),
            kwargs.get('ip_address'),
            kwargs['action'],
            kwargs.get('endpoint'),
            kwargs['success'],
            json.dumps(kwargs.get('details', {}))
        ))
        
        conn.commit()
        conn.close()
        logger.debug("Audit event logged successfully")

class RateLimiter:
    """Rate limiting for authentication attempts."""
    
    def __init__(self, config):
        self.config = config
        self.attempts = {}  # {ip: {user: [timestamps]}}
        self.lockouts = {}  # {ip: lockout_until}
        logger.info("Initializing rate limiter")
    
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
    
    def get_attempt_count(self, ip: str, username: str = None) -> int:
        """Get current attempt count for IP/user."""
        if ip not in self.attempts:
            return 0
        
        if username and username in self.attempts[ip]:
            return len(self.attempts[ip][username])
        
        return 0
