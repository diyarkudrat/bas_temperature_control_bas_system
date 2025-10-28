"""Authentication utility functions."""

from __future__ import annotations

import hashlib
import os
import random
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Tuple, Callable, TypeVar, Any, Optional


def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """Hash a password using PBKDF2-SHA256."""

    if salt is None:
        salt = secrets.token_bytes(32)

    iterations = 100000
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
    )

    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify a password against a stored hash and salt."""

    try:
        salt = bytes.fromhex(salt_hex)
        password_hash, _ = hash_password(password, salt)

        return secrets.compare_digest(password_hash, stored_hash)
    except Exception:
        return False


def create_session_fingerprint(user_agent: str, accept_language: str, accept_encoding: str, ip_address: str) -> str:
    """Create a session fingerprint."""
    
    components = [user_agent or '', accept_language or '', accept_encoding or '', ip_address or '']
    fingerprint_data = '|'.join(components)

    return hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()


def generate_session_id() -> str:
    """Generate a session ID."""

    return f"sess_{secrets.token_urlsafe(32)}"


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate the strength of a password."""

    if len(password) < 12:
        return False, "Password must be at least 12 characters"

    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"

    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letters"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain numbers"

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain special characters"

    common_passwords = {'password', '123456', 'admin', 'qwerty', 'password123', 'admin123'}
    normalized_password = ''.join(c for c in password.lower() if c.isalnum())

    if normalized_password in common_passwords:
        return False, "Password is too common"
        
    return True, "Password is valid"

# Generic type for a callable. Constraining F to Callable[..., Any] lets
# decorators (e.g., exponential_backoff) return a wrapper typed like the input
# function, preserving its signature for type checkers/IDE hints.
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
    """Decorator to retry a function with exponential backoff to prevent retry storms."""

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

                    delay = min(max_s, base_s * (2 ** (attempt - 1)))
                    if jitter > 0.0 and delay > 0.0:
                        delta = delay * jitter
                        delay = max(0.0, delay + random.uniform(-delta, delta))

                    time.sleep(delay)

            assert last_exc is not None
            raise last_exc

        return wrapper  # type: ignore[return-value]

    return decorator


def normalize_utc_timestamp(ts: float | int) -> str:
    """Normalize a UTC timestamp to ISO format."""

    try:
        value = float(ts)
    except Exception:
        value = 0.0

    if value > 1e12:
        value = value / 1000.0

    dt = datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0)

    return dt.isoformat().replace('+00:00', 'Z')


def now_ms(time_func: Callable[[], float] = time.time) -> int:
    """Get the current time in milliseconds."""

    return int(time_func() * 1000.0)


def monotonic_ms(monotonic_func: Callable[[], float] = time.monotonic) -> int:
    """Get the current time in milliseconds using a monotonic function."""

    return int(monotonic_func() * 1000.0)


def parse_authorization_header(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Parse an authorization header into scheme and token."""

    if not value or not isinstance(value, str):
        return None, None

    parts = value.strip().split()

    if len(parts) != 2:
        return None, None

    scheme, token = parts[0].lower(), parts[1]

    if not token:
        return None, None
        
    return scheme, token


