"""Authentication utility functions."""

import hashlib
import secrets
import time
import logging
from typing import Tuple

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

def generate_mfa_code(length: int = 6) -> str:
    """Generate random MFA code."""
    code = ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    logger.debug(f"Generated MFA code: {code[:2]}****")
    return code

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
    common_passwords = {'password', '123456', 'admin', 'qwerty', 'password123', 'admin123'}
    if password.lower() in common_passwords:
        logger.warning("Password is too common")
        return False, "Password is too common"
    
    logger.debug("Password strength validation passed")
    return True, "Password is valid"
