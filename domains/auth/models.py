from dataclasses import dataclass, field
import logging
import time
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
    user_id: str = "unknown"  # For Firestore compatibility
    tenant_id: Optional[str] = None  # For multi-tenant support

    def is_expired(self) -> bool:
        """Check if session has expired."""
        is_expired = time.time() > self.expires_at
        if is_expired:
            logger.debug(f"Session {self.session_id} has expired")
        return is_expired

