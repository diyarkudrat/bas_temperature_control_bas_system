"""Data models for authentication system."""

import time
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

@dataclass
class User:
    """User account model."""
    username: str
    password_hash: str
    salt: str
    phone_number: str
    role: str = "operator"  # "operator" | "admin" | "read-only"
    created_at: float = field(default_factory=time.time)
    last_login: float = 0
    failed_attempts: int = 0
    locked_until: float = 0
    password_history: List[str] = field(default_factory=list)
    mfa_enabled: bool = True
    
    def is_locked(self) -> bool:
        """Check if account is locked."""
        is_locked = self.locked_until > time.time()
        if is_locked:
            logger.warning(f"User {self.username} is locked until {self.locked_until}")
        return is_locked
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        logger.debug(f"Converting user {self.username} to dict")
        return {
            'username': self.username,
            'password_hash': self.password_hash,
            'salt': self.salt,
            'phone_number': self.phone_number,
            'role': self.role,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'failed_attempts': self.failed_attempts,
            'locked_until': self.locked_until,
            'password_history': json.dumps(self.password_history),
            'mfa_enabled': self.mfa_enabled
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """Create from dictionary."""
        logger.debug(f"Creating user from dict: {data.get('username', 'unknown')}")
        password_history = json.loads(data.get('password_history', '[]'))
        return cls(
            username=data['username'],
            password_hash=data['password_hash'],
            salt=data['salt'],
            phone_number=data['phone_number'],
            role=data.get('role', 'operator'),
            created_at=data.get('created_at', time.time()),
            last_login=data.get('last_login', 0),
            failed_attempts=data.get('failed_attempts', 0),
            locked_until=data.get('locked_until', 0),
            password_history=password_history,
            mfa_enabled=data.get('mfa_enabled', True)
        )

@dataclass
class Session:
    """Active session model."""
    session_id: str
    username: str
    role: str
    created_at: float
    expires_at: float
    last_access: float
    fingerprint: str
    ip_address: str
    user_agent: str
    mfa_verified: bool = True
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        is_expired = time.time() > self.expires_at
        if is_expired:
            logger.debug(f"Session {self.session_id} has expired")
        return is_expired
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        logger.debug(f"Converting session {self.session_id} to dict")
        return {
            'session_id': self.session_id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'last_access': self.last_access,
            'fingerprint': self.fingerprint,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'mfa_verified': self.mfa_verified
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        """Create from dictionary."""
        logger.debug(f"Creating session from dict: {data.get('session_id', 'unknown')}")
        return cls(
            session_id=data['session_id'],
            username=data['username'],
            role=data['role'],
            created_at=data['created_at'],
            expires_at=data['expires_at'],
            last_access=data['last_access'],
            fingerprint=data['fingerprint'],
            ip_address=data['ip_address'],
            user_agent=data['user_agent'],
            mfa_verified=data.get('mfa_verified', True)
        )

@dataclass
class PendingMFA:
    """Pending MFA verification model."""
    username: str
    code: str
    phone_number: str
    created_at: float
    expires_at: float
    
    def is_expired(self) -> bool:
        """Check if MFA code has expired."""
        is_expired = time.time() > self.expires_at
        if is_expired:
            logger.debug(f"MFA code for user {self.username} has expired")
        return is_expired
