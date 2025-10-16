"""Authentication configuration management."""

import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class AuthConfig:
    """Authentication system configuration."""
    
    # Feature flags
    auth_enabled: bool = True
    auth_mode: str = "user_password_mfa"  # "disabled" | "shadow" | "enforced"
    
    # Session settings
    session_timeout: int = 1800           # 30 minutes
    max_concurrent_sessions: int = 3
    session_rotation: bool = True
    
    # MFA settings
    mfa_code_expiry: int = 300            # 5 minutes
    mfa_code_length: int = 6
    sms_provider: str = "twilio"
    
    # Security settings
    max_login_attempts: int = 5
    lockout_duration: int = 900           # 15 minutes
    password_min_length: int = 12
    password_history_count: int = 5
    
    # Rate limiting
    rate_limit_per_ip: int = 100          # requests per hour
    rate_limit_per_user: int = 50         # requests per hour
    auth_attempts_per_15min: int = 5
    
    # Twilio settings
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_from_number: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> 'AuthConfig':
        """Load configuration from environment variables."""
        logger.info("Loading auth configuration from environment variables")
        return cls(
            auth_enabled=os.getenv('BAS_AUTH_ENABLED', 'true').lower() == 'true',
            auth_mode=os.getenv('BAS_AUTH_MODE', 'user_password_mfa'),
            session_timeout=int(os.getenv('BAS_SESSION_TIMEOUT', '1800')),
            max_concurrent_sessions=int(os.getenv('BAS_MAX_CONCURRENT_SESSIONS', '3')),
            max_login_attempts=int(os.getenv('BAS_MAX_LOGIN_ATTEMPTS', '5')),
            lockout_duration=int(os.getenv('BAS_LOCKOUT_DURATION', '900')),
            twilio_account_sid=os.getenv('TWILIO_ACCOUNT_SID'),
            twilio_auth_token=os.getenv('TWILIO_AUTH_TOKEN'),
            twilio_from_number=os.getenv('TWILIO_FROM_NUMBER')
        )
    
    @classmethod
    def from_file(cls, config_path: str) -> 'AuthConfig':
        """Load configuration from JSON file."""
        import json
        try:
            logger.info(f"Loading auth configuration from file: {config_path}")
            with open(config_path, 'r') as f:
                data = json.load(f)
            config = cls(**data)
            logger.info("Auth configuration loaded successfully")
            return config
        except FileNotFoundError:
            logger.warning(f"Auth config file not found: {config_path}, using defaults")
            return cls()
        except Exception as e:
            logger.error(f"Error loading auth config from {config_path}: {e}")
            return cls()
    
    def validate(self) -> bool:
        """Validate configuration settings."""
        logger.info("Validating auth configuration")
        
        if not self.auth_enabled:
            logger.info("Authentication disabled, skipping validation")
            return True
            
        if self.auth_mode == "disabled":
            logger.info("Authentication mode is disabled")
            return True
            
        # Validate required settings for enabled auth
        if self.auth_mode in ["shadow", "enforced"]:
            if not all([self.twilio_account_sid, self.twilio_auth_token, self.twilio_from_number]):
                logger.error("Twilio configuration incomplete for SMS MFA")
                return False
                
        # Validate numeric ranges
        if self.session_timeout < 300:  # Minimum 5 minutes
            logger.warning(f"Session timeout too short: {self.session_timeout}s")
            
        if self.max_concurrent_sessions < 1:
            logger.warning(f"Max concurrent sessions too low: {self.max_concurrent_sessions}")
            
        if self.password_min_length < 8:
            logger.warning(f"Password minimum length too low: {self.password_min_length}")
            
        logger.info("Auth configuration validation completed")
        return True
