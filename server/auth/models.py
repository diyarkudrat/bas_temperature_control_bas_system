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
    role: str = "operator"  # "operator" | "admin" | "read-only"
    created_at: float = field(default_factory=time.time)
    last_login: float = 0
    failed_attempts: int = 0
    locked_until: float = 0
    password_history: List[str] = field(default_factory=list)
    
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
            'role': self.role,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'failed_attempts': self.failed_attempts,
            'locked_until': self.locked_until,
            'password_history': json.dumps(self.password_history),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """Create from dictionary with input validation."""
        logger.debug(f"Creating user from dict: {data.get('username', 'unknown')}")
        
        # Validate and sanitize password history
        try:
            password_history = json.loads(data.get('password_history', '[]'))
            if not isinstance(password_history, list):
                password_history = []
        except (json.JSONDecodeError, TypeError):
            password_history = []
        
        # Validate numeric fields
        created_at = data.get('created_at', time.time())
        if not isinstance(created_at, (int, float)) or created_at < 0:
            created_at = time.time()
            
        last_login = data.get('last_login', 0)
        if not isinstance(last_login, (int, float)) or last_login < 0:
            last_login = 0
            
        failed_attempts = data.get('failed_attempts', 0)
        if not isinstance(failed_attempts, int) or failed_attempts < 0:
            failed_attempts = 0
            
        locked_until = data.get('locked_until', 0)
        if not isinstance(locked_until, (int, float)) or locked_until < 0:
            locked_until = 0
        
        # Validate role
        role = data.get('role', 'operator')
        if role not in ['operator', 'admin', 'read-only']:
            role = 'operator'
        
        return cls(
            username=data['username'],
            password_hash=data['password_hash'],
            salt=data['salt'],
            role=role,
            created_at=created_at,
            last_login=last_login,
            failed_attempts=failed_attempts,
            locked_until=locked_until,
            password_history=password_history,
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
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        """Create from dictionary with input validation."""
        logger.debug(f"Creating session from dict: {data.get('session_id', 'unknown')}")
        
        # Validate numeric fields
        created_at = data.get('created_at', time.time())
        if not isinstance(created_at, (int, float)) or created_at < 0:
            created_at = time.time()
            
        expires_at = data.get('expires_at', time.time() + 1800)
        if not isinstance(expires_at, (int, float)) or expires_at < created_at:
            expires_at = created_at + 1800
            
        last_access = data.get('last_access', time.time())
        if not isinstance(last_access, (int, float)) or last_access < created_at:
            last_access = created_at
        
        # Validate role
        role = data.get('role', 'operator')
        if role not in ['operator', 'admin', 'read-only']:
            role = 'operator'
        
        return cls(
            session_id=data['session_id'],
            username=data['username'],
            role=role,
            created_at=created_at,
            expires_at=expires_at,
            last_access=last_access,
            fingerprint=data['fingerprint'],
            ip_address=data['ip_address'],
            user_agent=data['user_agent'],
        )

