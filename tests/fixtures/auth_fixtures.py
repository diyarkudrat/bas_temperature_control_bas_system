"""
Authentication-specific test fixtures.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock
from typing import Generator

# Import auth modules (will be available due to conftest.py path setup)
from auth.config import AuthConfig
from auth.models import User, Session, PendingMFA
from auth.managers import UserManager, SessionManager, MFAManager


@pytest.fixture
def auth_config() -> AuthConfig:
    """Provide a default AuthConfig for testing."""
    return AuthConfig()


@pytest.fixture
def auth_config_with_twilio() -> AuthConfig:
    """Provide an AuthConfig with Twilio credentials for testing."""
    return AuthConfig(
        twilio_account_sid="test_sid",
        twilio_auth_token="test_token",
        twilio_from_number="+1234567890"
    )


@pytest.fixture
def disabled_auth_config() -> AuthConfig:
    """Provide a disabled AuthConfig for testing."""
    return AuthConfig(auth_enabled=False)


@pytest.fixture
def sample_user() -> User:
    """Provide a sample User object for testing."""
    return User(
        username="testuser",
        password_hash="hashed_password_123",
        salt="salt_123",
        phone_number="+1234567890",
        role="operator"
    )


@pytest.fixture
def sample_admin_user() -> User:
    """Provide a sample admin User object for testing."""
    return User(
        username="admin",
        password_hash="hashed_admin_password_123",
        salt="admin_salt_123",
        phone_number="+1987654321",
        role="admin"
    )


@pytest.fixture
def sample_session() -> Session:
    """Provide a sample Session object for testing."""
    import time
    return Session(
        session_id="sess_test_123",
        username="testuser",
        role="operator",
        created_at=time.time(),
        expires_at=time.time() + 3600,
        last_access=time.time(),
        fingerprint="test_fingerprint_123",
        ip_address="192.168.1.100",
        user_agent="Test Browser"
    )


@pytest.fixture
def sample_pending_mfa() -> PendingMFA:
    """Provide a sample PendingMFA object for testing."""
    import time
    return PendingMFA(
        username="testuser",
        code="123456",
        phone_number="+1234567890",
        created_at=time.time(),
        expires_at=time.time() + 300
    )


@pytest.fixture
def user_manager(temp_db_file: str, auth_config: AuthConfig) -> UserManager:
    """Provide a UserManager instance for testing."""
    return UserManager(temp_db_file, auth_config)


@pytest.fixture
def session_manager(temp_db_file: str, auth_config: AuthConfig) -> SessionManager:
    """Provide a SessionManager instance for testing."""
    return SessionManager(temp_db_file, auth_config)


@pytest.fixture
def mfa_manager(auth_config: AuthConfig) -> MFAManager:
    """Provide an MFAManager instance for testing."""
    return MFAManager(auth_config)


@pytest.fixture
def created_user(user_manager: UserManager) -> User:
    """Provide a pre-created user in the UserManager."""
    return user_manager.create_user(
        username="testuser",
        password="ValidPassword123!",
        phone_number="+1234567890",
        role="operator"
    )


@pytest.fixture
def created_admin_user(user_manager: UserManager) -> User:
    """Provide a pre-created admin user in the UserManager."""
    return user_manager.create_user(
        username="admin",
        password="AdminPassword123!",
        phone_number="+1987654321",
        role="admin"
    )
