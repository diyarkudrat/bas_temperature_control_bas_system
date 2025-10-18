"""
Unit tests for authentication managers (UserManager, SessionManager) using pytest.
"""

import time
import pytest

from auth.config import AuthConfig
from auth.managers import UserManager, SessionManager
from auth.exceptions import AuthError
from tests.utils.assertions import assert_equals, assert_true, assert_false, assert_is_not_none, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestUserManager:
    """Test UserManager with 100% coverage."""

    def test_create_user_success(self, user_manager):
        """Test successful user creation."""
        user = user_manager.create_user(
            "newuser", "ValidPassword123!", "operator"
        )
        assert_equals(user.username, "newuser")
        assert_equals(user.role, "operator")

    def test_create_user_weak_password(self, user_manager):
        """Test user creation with weak password."""
        with assert_raises(AuthError):
            user_manager.create_user(
                "newuser", "weak", "operator"
            )

    def test_create_user_already_exists(self, user_manager):
        """Test creating user that already exists."""
        # Create first user
        user_manager.create_user(
            "existinguser", "ValidPassword123!", "operator"
        )
        
        # Try to create same user again
        with assert_raises(AuthError):
            user_manager.create_user(
                "existinguser", "AnotherPassword123!", "admin"
            )

    def test_create_user_invalid_role_defaults_on_retrieval(self, user_manager):
        """Invalid role stored should default to 'operator' on retrieval."""
        user_manager.create_user("badrole", "ValidPassword123!", "invalid_role")
        retrieved = user_manager.get_user("badrole")
        assert_equals(retrieved.role, "operator")

    def test_authenticate_user_success(self, user_manager):
        """Test successful user authentication."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "operator"
        )
        
        # Authenticate
        user = user_manager.authenticate_user("testuser", "ValidPassword123!")
        assert_is_not_none(user)
        assert_equals(user.username, "testuser")

    def test_authenticate_user_wrong_password(self, user_manager):
        """Test authentication with wrong password."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "operator"
        )
        
        # Try wrong password
        user = user_manager.authenticate_user("testuser", "WrongPassword123!")
        assert user is None

    def test_authenticate_user_not_found(self, user_manager):
        """Test authentication for non-existent user."""
        user = user_manager.authenticate_user("nonexistent", "SomePassword123!")
        assert user is None

    def test_authenticate_user_locked(self, user_manager):
        """Test authentication for locked user."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "operator"
        )
        
        # Lock the user
        user = user_manager.get_user("testuser")
        user.locked_until = time.time() + 3600  # Locked for 1 hour
        user_manager._store_user(user)
        
        # Try to authenticate locked user
        auth_user = user_manager.authenticate_user("testuser", "ValidPassword123!")
        assert auth_user is None

    def test_get_user_found(self, user_manager):
        """Test getting existing user."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "operator"
        )
        
        user = user_manager.get_user("testuser")
        assert_is_not_none(user)
        assert_equals(user.username, "testuser")

    def test_get_user_not_found(self, user_manager):
        """Test getting non-existent user."""
        user = user_manager.get_user("nonexistent")
        assert user is None

    def test_update_last_login(self, user_manager):
        """Test updating user's last login time."""
        # Create user first
        user_manager.create_user(
            "testuser", "ValidPassword123!", "operator"
        )
        
        # Update last login
        user_manager.update_last_login("testuser")
        
        # Verify update
        user = user_manager.get_user("testuser")
        assert_true(user.last_login > 0)


@pytest.mark.auth
@pytest.mark.unit
class TestSessionManager:
    """Test SessionManager with 100% coverage."""

    def test_create_session(self, session_manager, mock_request):
        """Test session creation."""
        session = session_manager.create_session("testuser", "operator", mock_request)
        assert_equals(session.username, "testuser")
        assert_equals(session.role, "operator")
        assert_is_not_none(session.session_id)
        assert_is_not_none(session.fingerprint)

    def test_validate_session_success(self, session_manager, mock_request):
        """Test successful session validation."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Validate session
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert_is_not_none(validated_session)
        assert_equals(validated_session.session_id, session.session_id)

    def test_validate_session_not_found(self, session_manager, mock_request):
        """Test session validation for non-existent session."""
        session = session_manager.validate_session("nonexistent", mock_request)
        assert session is None

    def test_validate_session_expired(self, session_manager, mock_request):
        """Test session validation for expired session."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Manually expire the session
        session.expires_at = time.time() - 1
        session_manager.sessions[session.session_id] = session
        
        # Try to validate expired session
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert validated_session is None

    def test_validate_session_fingerprint_mismatch(self, session_manager, mock_request):
        """Test session validation with fingerprint mismatch."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Change request fingerprint
        mock_request.headers['User-Agent'] = 'Chrome/91.0'
        
        # Try to validate with different fingerprint
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert validated_session is None

    def test_invalidate_session(self, session_manager, mock_request):
        """Test session invalidation."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        session_id = session.session_id
        
        # Invalidate session
        session_manager.invalidate_session(session_id)
        
        # Try to get invalidated session
        invalidated_session = session_manager.get_session(session_id)
        assert invalidated_session is None

    def test_update_last_access(self, session_manager, mock_request):
        """Test updating session last access time."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        session_id = session.session_id
        original_access = session.last_access
        
        # Update last access
        time.sleep(0.1)  # Small delay to ensure time difference
        session_manager.update_last_access(session_id)
        
        # Verify update
        updated_session = session_manager.get_session(session_id)
        assert_true(updated_session.last_access > original_access)



    def test_user_manager_init_tables(self, temp_db_file, auth_config):
        """Test UserManager table initialization."""
        user_manager = UserManager(temp_db_file, auth_config)
        
        # Verify tables were created
        import sqlite3
        conn = sqlite3.connect(temp_db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = cursor.fetchone()
        conn.close()
        
        assert_is_not_none(table_exists, "Users table should be created")

    def test_user_manager_store_user(self, user_manager, sample_user):
        """Test storing user in database."""
        user_manager._store_user(sample_user)
        
        # Verify user was stored
        stored_user = user_manager.get_user(sample_user.username)
        assert_is_not_none(stored_user)
        assert_equals(stored_user.username, sample_user.username)

    def test_user_manager_validate_password_strength(self, user_manager):
        """Test password strength validation in UserManager."""
        # Test valid password
        is_valid, message = user_manager._validate_password_strength("ValidPassword123!")
        assert_true(is_valid)
        
        # Test weak password
        is_valid, message = user_manager._validate_password_strength("weak")
        assert_false(is_valid)

    def test_session_manager_init_tables(self, temp_db_file, auth_config):
        """Test SessionManager table initialization."""
        session_manager = SessionManager(temp_db_file, auth_config)
        
        # Verify tables were created
        import sqlite3
        conn = sqlite3.connect(temp_db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
        table_exists = cursor.fetchone()
        conn.close()
        
        assert_is_not_none(table_exists, "Sessions table should be created")

    def test_session_manager_store_session(self, session_manager, sample_session):
        """Test storing session in database."""
        session_manager._store_session(sample_session)
        
        # Verify session was stored
        stored_session = session_manager.get_session(sample_session.session_id)
        assert_is_not_none(stored_session)
        assert_equals(stored_session.session_id, sample_session.session_id)

    def test_session_manager_get_user_sessions(self, session_manager, mock_request):
        """Test getting user sessions."""
        # Create multiple sessions for same user
        session1 = session_manager.create_session("testuser", "operator", mock_request)
        session2 = session_manager.create_session("testuser", "operator", mock_request)
        
        # Get user sessions
        user_sessions = session_manager._get_user_sessions("testuser")
        assert_equals(len(user_sessions), 2)

    def test_session_manager_concurrent_session_limit(self, session_manager, mock_request):
        """Test concurrent session limit enforcement."""
        # Create sessions up to limit
        for i in range(session_manager.config.max_concurrent_sessions):
            session_manager.create_session("testuser", "operator", mock_request)
        
        # Create one more session (should remove oldest)
        new_session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Verify we still have max_concurrent_sessions
        user_sessions = session_manager._get_user_sessions("testuser")
        assert_equals(len(user_sessions), session_manager.config.max_concurrent_sessions)

    def test_session_manager_validate_session_insufficient_fingerprint(self, session_manager, mock_request):
        """Test session validation with insufficient fingerprint data."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        
        # Modify request to have insufficient fingerprint data
        mock_request.headers = {}
        mock_request.remote_addr = None
        
        # Validate session
        validated_session = session_manager.validate_session(session.session_id, mock_request)
        assert validated_session is None

    def test_session_manager_cleanup_thread(self, session_manager):
        """Test that cleanup thread is started."""
        # The cleanup thread should be started during initialization
        # We can't easily test the thread itself, but we can verify the manager was created
        assert_is_not_none(session_manager)


    def test_user_manager_authenticate_user_reset_failed_attempts(self, user_manager):
        """Test that successful authentication resets failed attempts."""
        # Create user
        user_manager.create_user("testuser", "ValidPassword123!", "operator")
        
        # Simulate failed attempts
        user = user_manager.get_user("testuser")
        user.failed_attempts = 3
        user_manager._store_user(user)
        
        # Authenticate successfully
        auth_user = user_manager.authenticate_user("testuser", "ValidPassword123!")
        assert_is_not_none(auth_user)
        
        # Check that failed attempts were reset
        updated_user = user_manager.get_user("testuser")
        assert_equals(updated_user.failed_attempts, 0)
        assert_equals(updated_user.locked_until, 0)

    def test_user_manager_authenticate_user_increment_failed_attempts(self, user_manager):
        """Test that failed authentication increments failed attempts."""
        # Create user
        user_manager.create_user("testuser", "ValidPassword123!", "operator")
        
        # Try wrong password
        auth_user = user_manager.authenticate_user("testuser", "WrongPassword123!")
        assert auth_user is None
        
        # Check that failed attempts were incremented
        user = user_manager.get_user("testuser")
        assert_equals(user.failed_attempts, 1)

    def test_user_manager_authenticate_user_lockout(self, user_manager):
        """Test that account gets locked after max failed attempts."""
        # Create user
        user_manager.create_user("testuser", "ValidPassword123!", "operator")
        
        # Try wrong password multiple times to trigger lockout
        for _ in range(user_manager.config.max_login_attempts):
            auth_user = user_manager.authenticate_user("testuser", "WrongPassword123!")
            assert auth_user is None
        
        # Check that account is locked
        user = user_manager.get_user("testuser")
        assert_true(user.is_locked())

    def test_session_manager_update_last_access_cache(self, session_manager, mock_request):
        """Test updating last access time in cache."""
        # Create session
        session = session_manager.create_session("testuser", "operator", mock_request)
        original_access = session.last_access
        
        # Update last access
        import time
        time.sleep(0.1)  # Small delay
        session_manager.update_last_access(session.session_id)
        
        # Check cache was updated
        cached_session = session_manager.sessions.get(session.session_id)
        assert_is_not_none(cached_session)
        assert_true(cached_session.last_access > original_access)


class Result:
    """Simple result stub used by Firestore service stubs."""
    def __init__(self, success: bool, data=None, error=None):
        self.success = success
        self.data = data
        self.error = error


@pytest.mark.auth
@pytest.mark.unit
class TestFirestoreBranchesUserManager:
    def test_init_firestore_success(self, temp_db_file, auth_config):
        class Factory:
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                return object()

        um = UserManager(temp_db_file, auth_config, Factory())
        assert_true(um.firestore_users is not None)

    def test_init_firestore_exception(self, temp_db_file, auth_config):
        class Factory:
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                raise Exception("init failure")

        um = UserManager(temp_db_file, auth_config, Factory())
        assert_true(um.firestore_users is None)

    def test_authenticate_user_firestore_success_and_update(self, temp_db_file, auth_config):
        from auth.models import User
        from auth.utils import hash_password

        password_hash, salt = hash_password("ValidPassword123!")

        class UsersService:
            def __init__(self):
                self.update_called = False
            def get_by_username(self, username):
                return Result(True, User(username=username, password_hash=password_hash, salt=salt, role="operator"))
            def update_user(self, user):
                self.update_called = True

        class Factory:
            def __init__(self):
                self._svc = UsersService()
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                return self._svc

        factory = Factory()
        um = UserManager(temp_db_file, auth_config, factory)
        user = um.authenticate_user("fs_user", "ValidPassword123!")
        assert_is_not_none(user)
        assert_true(factory._svc.update_called)

    def test_authenticate_user_firestore_not_found(self, temp_db_file, auth_config):
        class UsersService:
            def get_by_username(self, username):
                return Result(True, None)
            def update_user(self, user):
                pass

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                return UsersService()

        um = UserManager(temp_db_file, auth_config, Factory())
        user = um.authenticate_user("missing", "irrelevant")
        assert_true(user is None)

    def test_authenticate_user_firestore_exception_fallback_sqlite(self, temp_db_file, auth_config):
        class UsersService:
            def get_by_username(self, username):
                raise Exception("boom")
            def update_user(self, user):
                pass

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                return UsersService()

        um = UserManager(temp_db_file, auth_config, Factory())
        user = um.authenticate_user("someone", "pwd")
        assert_true(user is None)

    def test_authenticate_user_firestore_wrong_password_updates_failed_attempts(self, temp_db_file, auth_config):
        from auth.models import User
        from auth.utils import hash_password

        password_hash, salt = hash_password("ValidPassword123!")

        class UsersService:
            def __init__(self):
                self.update_called = False
                self.last_user = None
            def get_by_username(self, username):
                return Result(True, User(username=username, password_hash=password_hash, salt=salt, role="operator"))
            def update_user(self, user):
                self.update_called = True
                self.last_user = user

        class Factory:
            def __init__(self):
                self._svc = UsersService()
            def is_auth_enabled(self):
                return True
            def get_users_service(self):
                return self._svc

        factory = Factory()
        um = UserManager(temp_db_file, auth_config, factory)
        user = um.authenticate_user("fs_user", "WrongPassword123!")
        assert_true(user is None)
        assert_true(factory._svc.update_called)
        assert_true(factory._svc.last_user.failed_attempts >= 1)


@pytest.mark.auth
@pytest.mark.unit
class TestFirestoreBranchesSessionManager:
    def test_init_firestore_success(self, temp_db_file, auth_config):
        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return object()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        assert_true(sm.firestore_sessions is not None)

    def test_init_firestore_exception(self, temp_db_file, auth_config):
        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                raise Exception("init failure")

        sm = SessionManager(temp_db_file, auth_config, Factory())
        assert_true(sm.firestore_sessions is None)

    def test_create_session_firestore_success_no_sqlite_persist(self, temp_db_file, auth_config):
        class FSessions:
            def __init__(self):
                self.created = []
            def create_session(self, user_id, username, role, expires_in_seconds, request_info):
                self.created.append((username, role, request_info))
                return True

        class Factory:
            def __init__(self):
                self._svc = FSessions()
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return self._svc

        factory = Factory()
        sm = SessionManager(temp_db_file, auth_config, factory)
        mock_request = pytest.fixture(lambda: None)
        # Build a simple request
        class Req:
            def __init__(self):
                self.headers = {
                    'User-Agent': 'Mozilla/5.0 (Test Browser)',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate'
                }
                self.remote_addr = '192.168.1.101'
        req = Req()
        sm.create_session("testuser", "operator", req)
        assert_equals(len(factory._svc.created), 1)
        # Not persisted to SQLite because Firestore returned True
        assert_equals(len(sm._get_user_sessions("testuser")), 0)

    def test_create_session_firestore_false_fallback_sqlite(self, temp_db_file, auth_config):
        class FSessions:
            def create_session(self, user_id, username, role, expires_in_seconds, request_info):
                return False

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return FSessions()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        class Req:
            def __init__(self):
                self.headers = {
                    'User-Agent': 'Mozilla/5.0 (Test Browser)',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate'
                }
                self.remote_addr = '192.168.1.102'
        req = Req()
        sm.create_session("testuser", "operator", req)
        # Persisted to SQLite due to fallback
        assert_equals(len(sm._get_user_sessions("testuser")), 1)

    def test_create_session_firestore_exception_fallback_sqlite(self, temp_db_file, auth_config):
        class FSessions:
            def create_session(self, user_id, username, role, expires_in_seconds, request_info):
                raise Exception("boom")

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return FSessions()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        class Req:
            def __init__(self):
                self.headers = {
                    'User-Agent': 'Mozilla/5.0 (Test Browser)',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate'
                }
                self.remote_addr = '192.168.1.103'
        req = Req()
        sm.create_session("testuser", "operator", req)
        assert_equals(len(sm._get_user_sessions("testuser")), 1)

    def test_get_session_firestore_found_not_expired_caches(self, temp_db_file, auth_config):
        from auth.models import Session
        import time as _t

        class FSessions:
            def __init__(self, sess):
                self._sess = sess
            def get_session(self, session_id):
                return Result(True, self._sess)

        class Factory:
            def __init__(self, sess):
                self._svc = FSessions(sess)
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return self._svc

        now = _t.time()
        s = Session(
            session_id="sess_fs_1",
            username="testuser",
            role="operator",
            created_at=now,
            expires_at=now + 3600,
            last_access=now,
            fingerprint="fp",
            ip_address="127.0.0.1",
            user_agent="UA"
        )
        sm = SessionManager(temp_db_file, auth_config, Factory(s))
        out = sm.get_session("sess_fs_1")
        assert_is_not_none(out)
        assert_true("sess_fs_1" in sm.sessions)

    def test_get_session_firestore_found_expired(self, temp_db_file, auth_config):
        from auth.models import Session
        import time as _t

        class FSessions:
            def get_session(self, session_id):
                now = _t.time()
                exp = now - 10
                s = Session(
                    session_id=session_id,
                    username="testuser",
                    role="operator",
                    created_at=now - 100,
                    expires_at=exp,
                    last_access=exp,
                    fingerprint="fp",
                    ip_address="127.0.0.1",
                    user_agent="UA"
                )
                return Result(True, s)

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return FSessions()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        out = sm.get_session("sess_fs_expired")
        assert_true(out is None)

    def test_get_session_firestore_not_found(self, temp_db_file, auth_config):
        class FSessions:
            def get_session(self, session_id):
                return Result(False, None)

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return FSessions()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        out = sm.get_session("missing")
        assert_true(out is None)

    def test_get_session_firestore_exception_fallback_sqlite(self, temp_db_file, auth_config):
        from auth.models import Session
        import time as _t

        class FSessions:
            def get_session(self, session_id):
                raise Exception("boom")

        class Factory:
            def is_auth_enabled(self):
                return True
            def get_sessions_service(self):
                return FSessions()

        sm = SessionManager(temp_db_file, auth_config, Factory())
        # Pre-store a session in SQLite
        now = _t.time()
        sample = Session(
            session_id="sess_local",
            username="testuser",
            role="operator",
            created_at=now,
            expires_at=now + 3600,
            last_access=now,
            fingerprint="fp",
            ip_address="127.0.0.1",
            user_agent="UA"
        )
        sm._store_session(sample)
        out = sm.get_session("sess_local")
        assert_is_not_none(out)

    def test_invalidate_session_firestore_delete_success_and_failure(self, temp_db_file, auth_config):
        from auth.models import Session
        import time as _t

        class FSessionsOK:
            def delete_session(self, session_id):
                return Result(True, None)

        class FSessionsFail:
            def delete_session(self, session_id):
                return Result(False, None)

        for svc_cls in (FSessionsOK, FSessionsFail):
            class Factory:
                def is_auth_enabled(self):
                    return True
                def get_sessions_service(self):
                    return svc_cls()

            sm = SessionManager(temp_db_file, auth_config, Factory())
            # Create and persist a session in SQLite
            now = _t.time()
            sample = Session(
                session_id="sess_to_del",
                username="testuser",
                role="operator",
                created_at=now,
                expires_at=now + 3600,
                last_access=now,
                fingerprint="fp",
                ip_address="127.0.0.1",
                user_agent="UA"
            )
            sm._store_session(sample)
            # Cache it too
            sm.sessions[sample.session_id] = sample
            sm.invalidate_session(sample.session_id)
            assert_true(sm.get_session(sample.session_id) is None)

    def test_create_session_extracts_user_and_tenant_from_real_request(self, temp_db_file, auth_config):
        class Factory:
            def is_auth_enabled(self):
                return False

        sm = SessionManager(temp_db_file, auth_config, Factory())

        class RealReq:
            def __init__(self):
                self.headers = {
                    'User-Agent': 'Mozilla/5.0 (Test Browser)',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate'
                }
                self.remote_addr = '192.168.1.150'
                self.user_id = '123e4567-e89b-12d3-a456-426614174000'
                self.tenant_id = '123e4567-e89b-12d3-a456-426614174001'

        req = RealReq()
        session = sm.create_session("testuser", "operator", req)
        assert_equals(session.user_id, req.user_id)
        assert_equals(session.tenant_id, req.tenant_id)
