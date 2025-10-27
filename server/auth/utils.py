"""Authentication utility functions."""

import hashlib
import secrets
import time
import logging
import os
import random
from functools import wraps
from typing import Tuple, Callable, TypeVar, Any, Optional
from datetime import datetime

from .metadata_limiter import rate_limit_metadata_fetch  # re-export

logger = logging.getLogger(__name__)


def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-SHA256."""
    logger.debug("Hashing password")
    
    if salt is None:
        salt = secrets.token_bytes(32)
        logger.debug("Generated new salt for password")
    
    # Use PBKDF2 with 100,000 iterations (adjustable for performance)
    iterations = 100000
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    
    logger.debug("Password hashed successfully")
    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify password against stored hash using constant-time comparison."""
    logger.debug("Verifying password")
    
    try:
        salt = bytes.fromhex(salt_hex)
        password_hash, _ = hash_password(password, salt)
        
        # Constant-time comparison to prevent timing attacks
        is_valid = secrets.compare_digest(password_hash, stored_hash)
        logger.debug(f"Password verification result: {is_valid}")
        return is_valid
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def create_session_fingerprint(user_agent: str, accept_language: str, 
                              accept_encoding: str, ip_address: str) -> str:
    """Create session fingerprint for security."""
    logger.debug("Creating session fingerprint")
    
    components = [
        user_agent or '',
        accept_language or '',
        accept_encoding or '',
        ip_address or ''
    ]
    fingerprint_data = '|'.join(components)
    fingerprint = hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()
    
    logger.debug(f"Session fingerprint created: {fingerprint[:8]}...")
    return fingerprint


def generate_session_id() -> str:
    """Generate secure session ID."""
    session_id = f"sess_{secrets.token_urlsafe(32)}"
    logger.debug(f"Generated session ID: {session_id[:12]}...")
    return session_id


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password against security policy."""
    logger.debug("Validating password strength")
    
    if len(password) < 12:
        logger.warning("Password too short")
        return False, "Password must be at least 12 characters"
    
    if not any(c.isupper() for c in password):
        logger.warning("Password missing uppercase letters")
        return False, "Password must contain uppercase letters"
    
    if not any(c.islower() for c in password):
        logger.warning("Password missing lowercase letters")
        return False, "Password must contain lowercase letters"
    
    if not any(c.isdigit() for c in password):
        logger.warning("Password missing digits")
        return False, "Password must contain numbers"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        logger.warning("Password missing special characters")
        return False, "Password must contain special characters"
    
    # Check against common passwords (simplified)
    # Normalize by lowercasing and stripping non-alphanumeric to catch variants
    common_passwords = {'password', '123456', 'admin', 'qwerty', 'password123', 'admin123'}
    normalized_password = ''.join(c for c in password.lower() if c.isalnum())
    if normalized_password in common_passwords:
        logger.warning("Password is too common")
        return False, "Password is too common"
    
    logger.debug("Password strength validation passed")
    return True, "Password is valid"


F = TypeVar("F", bound=Callable[..., Any])


def exponential_backoff(
    *,
    max_tries: int = 5,
    base: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.1,
    config_via_env: bool = True,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    retry_if: Optional[Callable[[BaseException], bool]] = None,
) -> Callable[[F], F]:
    """Decorator to retry a function with exponential backoff.

    Env overrides when config_via_env is True:
      BAS_BACKOFF_MAX_TRIES, BAS_BACKOFF_BASE_S, BAS_BACKOFF_MAX_DELAY_S
    """

    tries = int(os.getenv("BAS_BACKOFF_MAX_TRIES", str(max_tries))) if config_via_env else max_tries
    base_s = float(os.getenv("BAS_BACKOFF_BASE_S", str(base))) if config_via_env else base
    max_s = float(os.getenv("BAS_BACKOFF_MAX_DELAY_S", str(max_delay))) if config_via_env else max_delay

    tries = max(1, tries)
    base_s = max(0.0, base_s)
    max_s = max(0.0, max_s)

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any):  # type: ignore[override]
            attempt = 0
            last_exc: Optional[BaseException] = None
            while attempt < tries:
                attempt += 1
                try:
                    return func(*args, **kwargs)
                except retry_on as exc:  # noqa: BLE001
                    if retry_if is not None and not retry_if(exc):
                        raise
                    last_exc = exc
                    if attempt >= tries:
                        break
                    # exponential delay with bounded jitter
                    delay = min(max_s, base_s * (2 ** (attempt - 1)))
                    if jitter > 0.0 and delay > 0.0:
                        # jitter in +-jitter*delay range
                        delta = delay * jitter
                        delay = max(0.0, delay + random.uniform(-delta, delta))
                    time.sleep(delay)
            assert last_exc is not None
            raise last_exc

        return wrapper  # type: ignore[return-value]

    return decorator


def normalize_utc_timestamp(ts: float | int) -> str:
    """Normalize epoch timestamp (seconds or milliseconds) to UTC ISO string with 'Z'."""
    try:
        value = float(ts)
    except Exception:
        value = 0.0
    # If the value looks like milliseconds, convert to seconds
    if value > 1e12:
        value = value / 1000.0
    # Truncate microseconds for stable outputs
    dt = datetime.utcfromtimestamp(value).replace(microsecond=0)
    return dt.isoformat() + 'Z'


def now_ms(time_func: Callable[[], float] = time.time) -> int:
    """Return current epoch time in milliseconds using provided time function."""
    return int(time_func() * 1000.0)


def monotonic_ms(monotonic_func: Callable[[], float] = time.monotonic) -> int:
    """Return monotonic time in milliseconds using provided monotonic function."""
    return int(monotonic_func() * 1000.0)


def parse_authorization_header(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Parse Authorization header into (scheme, token). Returns (None, None) if invalid."""
    if not value or not isinstance(value, str):
        return None, None
    parts = value.strip().split()
    if len(parts) != 2:
        return None, None
    scheme, token = parts[0].lower(), parts[1]
    if not token:
        return None, None
    return scheme, token
