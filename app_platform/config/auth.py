"""Authentication configuration management."""

import json
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication system configuration."""

    # Feature flags
    auth_enabled: bool = True
    auth_mode: str = "user_password"  # "disabled" | "shadow" | "enforced"

    # Firestore feature flags
    use_firestore_telemetry: bool = False
    use_firestore_auth: bool = False
    use_firestore_audit: bool = False

    # Org onboarding feature flags
    org_signup_v2_enabled: bool = False
    device_rbac_enforcement: bool = False

    # Firestore configuration
    gcp_project_id: str | None = None
    firestore_emulator_host: str | None = None
    tenant_id_header: str = "X-BAS-Tenant"

    # Session settings
    session_timeout: int = 1800  # 30 minutes
    max_concurrent_sessions: int = 3
    session_rotation: bool = True

    # Security settings
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    password_min_length: int = 12
    password_history_count: int = 5

    # Rate limiting
    rate_limit_per_ip: int = 100  # requests per hour
    rate_limit_per_user: int = 50  # requests per hour
    auth_attempts_per_15min: int = 5

    # Provisioning / invite settings
    provisioning_key_id: str | None = None
    provisioning_private_key_secret: str | None = None
    provisioning_jwt_ttl_seconds: int = 60
    invite_quota_per_tenant: int = 20
    invite_quota_window_minutes: int = 60
    invite_ttl_hours: int = 72
    default_device_quota: int = 100
    idempotency_ttl_hours: int = 24
    replay_cache_ttl_seconds: int = 120
    auth0_webhook_secret: str | None = None

    # CAPTCHA configuration
    captcha_provider: str | None = None
    captcha_site_key: str | None = None
    captcha_secret_handle: str | None = None
    captcha_min_score: float = 0.5

    @classmethod
    def from_env(cls) -> "AuthConfig":
        """Load configuration from environment variables."""

        logger.info("Loading auth configuration from environment variables")
        return cls(
            auth_enabled=os.getenv("BAS_AUTH_ENABLED", "true").lower() == "true",
            auth_mode=os.getenv("BAS_AUTH_MODE", "user_password"),
            use_firestore_telemetry=os.getenv("USE_FIRESTORE_TELEMETRY", "0") == "1",
            use_firestore_auth=os.getenv("USE_FIRESTORE_AUTH", "0") == "1",
            use_firestore_audit=os.getenv("USE_FIRESTORE_AUDIT", "0") == "1",
            org_signup_v2_enabled=os.getenv("ORG_SIGNUP_V2", "0") in {"1", "true", "True"},
            device_rbac_enforcement=os.getenv("DEVICE_RBAC_ENFORCEMENT", "0") in {"1", "true", "True"},
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
            firestore_emulator_host=os.getenv("FIRESTORE_EMULATOR_HOST"),
            tenant_id_header=os.getenv("TENANT_ID_HEADER", "X-BAS-Tenant"),
            session_timeout=int(os.getenv("BAS_SESSION_TIMEOUT", "1800")),
            max_concurrent_sessions=int(os.getenv("BAS_MAX_CONCURRENT_SESSIONS", "3")),
            max_login_attempts=int(os.getenv("BAS_MAX_LOGIN_ATTEMPTS", "5")),
            lockout_duration=int(os.getenv("BAS_LOCKOUT_DURATION", "900")),
            provisioning_key_id=os.getenv("ORG_SIGNUP_SIGNING_KEY_ID"),
            provisioning_private_key_secret=os.getenv("ORG_SIGNUP_PRIVATE_KEY_SECRET"),
            provisioning_jwt_ttl_seconds=int(os.getenv("ORG_SIGNUP_JWT_TTL_SECONDS", "60")),
            invite_quota_per_tenant=int(os.getenv("INVITE_MAX_PER_TENANT", "20")),
            invite_quota_window_minutes=int(os.getenv("INVITE_QUOTA_WINDOW_MINUTES", "60")),
            invite_ttl_hours=int(os.getenv("INVITE_TTL_HOURS", "72")),
            default_device_quota=int(os.getenv("DEFAULT_DEVICE_QUOTA", "100")),
            idempotency_ttl_hours=int(os.getenv("IDEMPOTENCY_TTL_HOURS", "24")),
            replay_cache_ttl_seconds=int(os.getenv("REQUEST_JWT_REPLAY_TTL_SECONDS", "120")),
            auth0_webhook_secret=os.getenv("AUTH0_WEBHOOK_SECRET"),
            captcha_provider=os.getenv("CAPTCHA_PROVIDER"),
            captcha_site_key=os.getenv("CAPTCHA_SITE_KEY"),
            captcha_secret_handle=os.getenv("CAPTCHA_SECRET_HANDLE"),
            captcha_min_score=float(os.getenv("CAPTCHA_MIN_SCORE", "0.5")),
        )

    @classmethod
    def from_file(cls, config_path: str) -> "AuthConfig":
        """Load configuration from JSON file."""
        
        try:
            logger.info(f"Loading auth configuration from file: {config_path}")
            with open(config_path, "r") as f:
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

        if self.session_timeout < 300:  # Minimum 5 minutes
            logger.warning(f"Session timeout too short: {self.session_timeout}s")

        if self.max_concurrent_sessions < 1:
            logger.warning(f"Max concurrent sessions too low: {self.max_concurrent_sessions}")

        if self.password_min_length < 8:
            logger.warning(f"Password minimum length too low: {self.password_min_length}")

        if self.org_signup_v2_enabled:
            if not self.provisioning_key_id:
                logger.warning("ORG_SIGNUP_V2 enabled without provisioning key id")
            if not self.provisioning_private_key_secret:
                logger.warning("ORG_SIGNUP_V2 enabled without provisioning key secret handle")
            if self.provisioning_jwt_ttl_seconds < 30 or self.provisioning_jwt_ttl_seconds > 300:
                logger.warning(
                    "Provisioning JWT TTL outside recommended range",
                    extra={"ttl": self.provisioning_jwt_ttl_seconds},
                )

        if self.captcha_provider and not self.captcha_secret_handle:
            logger.warning(
                "Captcha provider configured without secret handle",
                extra={"provider": self.captcha_provider},
            )

        if self.invite_quota_per_tenant <= 0:
            logger.warning("invite_quota_per_tenant must be positive")

        logger.info("Auth configuration validation completed")
        
        return True


