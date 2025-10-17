"""Tests for UsersRepository."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    UsersRepository, MockUser as User, create_mock_user as create_user, 
    validate_mock_username as validate_username, validate_mock_role as validate_role,
    OperationResult, QueryOptions, PaginatedResult, FirestoreError, PermissionError, ValidationError,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_instance, assert_raises, assert_is_none


@pytest.mark.auth
@pytest.mark.unit
class TestUsersRepository:
    """Test cases for UsersRepository."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def users_repo(self, mock_client):
        """Create UsersRepository instance."""
        return UsersRepository(mock_client)
    
    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing."""
        return User(
            username="testuser",
            password_hash="hashed_password_123",
            salt="salt_123",
            role="operator"
        )
    
    def test_init(self, mock_client):
        """Test repository initialization."""
        repo = UsersRepository(mock_client)
        assert repo.client == mock_client
        assert repo.collection == mock_client.collection.return_value
        assert repo.required_fields == ['username', 'password_hash', 'salt']
    
    def test_create_success(self, users_repo, sample_user):
        """Test successful user creation."""
        with patch.object(users_repo, '_validate_required_fields') as mock_validate:
            with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_username', return_value=True) as mock_validate_username:
                with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_role', return_value=True) as mock_validate_role:
                    with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
                        with patch.object(users_repo, '_add_timestamps') as mock_add_timestamps:
                            mock_get_by_username.return_value = OperationResult(success=False, error="User not found")
                            mock_add_timestamps.return_value = sample_user.to_dict()
                            
                            result = users_repo.create(sample_user)
                            
                            assert_true(result.success, "Create should succeed")
                            assert_equals(result.data, sample_user.user_id, "Should return user ID")
                            users_repo.collection.document.return_value.set.assert_called_once()
    
    def test_create_invalid_username(self, users_repo, sample_user):
        """Test create with invalid username."""
        # Patch the validation function in the mock_users_store module
        with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_username', return_value=False) as mock_validate_username:
            with assert_raises(ValueError):
                users_repo.create(sample_user)
    
    def test_create_invalid_role(self, users_repo, sample_user):
        """Test create with invalid role."""
        with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_username', return_value=True) as mock_validate_username:
            with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_role', return_value=False) as mock_validate_role:
                with assert_raises(ValueError):
                    users_repo.create(sample_user)
    
    def test_create_username_exists(self, users_repo, sample_user):
        """Test create when username already exists."""
        with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_username', return_value=True) as mock_validate_username:
            with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_role', return_value=True) as mock_validate_role:
                with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
                    mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
                    
                    result = users_repo.create(sample_user)
                    
                    assert_false(result.success, "Create should fail")
                    assert_equals(result.error, "Username already exists", "Should return username exists error")
                    assert_equals(result.error_code, "USERNAME_EXISTS", "Should return correct error code")
    
    def test_create_permission_denied(self, users_repo, sample_user):
        """Test create with permission denied error."""
        with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_username', return_value=True) as mock_validate_username:
            with patch('tests.unit.firestore.mock.mock_users_store.validate_mock_role', return_value=True) as mock_validate_role:
                with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
                    with patch.object(users_repo, '_add_timestamps') as mock_add_timestamps:
                        mock_get_by_username.return_value = OperationResult(success=False, error="User not found")
                        mock_add_timestamps.return_value = sample_user.to_dict()
                        
                        users_repo.collection.document.return_value.set.side_effect = PermissionDenied("Permission denied")
                        
                        with assert_raises(PermissionError):
                            users_repo.create(sample_user)
    
    def test_get_by_id_success(self, users_repo, sample_user):
        """Test successful get by ID."""
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.id = "test_user_id"
        mock_doc.to_dict.return_value = sample_user.to_dict()
        
        users_repo.collection.document.return_value.get.return_value = mock_doc
        
        with patch.object(create_user, '__call__', return_value=sample_user) as mock_create_user:
            mock_create_user.return_value = sample_user
            
            result = users_repo.get_by_id("test_user_id")
            
            assert_true(result.success, "Get should succeed")
            assert_is_not_none(result.data, "Should return user")
            assert_equals(result.data.id, "test_user_id", "Should set document ID")
    
    def test_get_by_id_not_found(self, users_repo):
        """Test get by ID when user doesn't exist."""
        mock_doc = Mock()
        mock_doc.exists = False
        
        users_repo.collection.document.return_value.get.return_value = mock_doc
        
        result = users_repo.get_by_id("nonexistent_id")
        
        assert_false(result.success, "Get should fail")
        assert_equals(result.error, "User not found", "Should return not found error")
        assert_equals(result.error_code, "NOT_FOUND", "Should return correct error code")
    
    def test_get_by_id_permission_denied(self, users_repo):
        """Test get by ID with permission denied error."""
        users_repo.collection.document.return_value.get.side_effect = PermissionDenied("Permission denied")
        
        with assert_raises(PermissionError):
            users_repo.get_by_id("test_id")
    
    def test_update_success(self, users_repo, sample_user):
        """Test successful user update."""
        updates = {'role': 'admin'}
        
        with patch.object(users_repo, '_add_timestamps') as mock_add_timestamps:
            with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
                mock_add_timestamps.return_value = updates
                mock_get_by_id.return_value = OperationResult(success=True, data=sample_user)
                
                result = users_repo.update("test_user_id", updates)
                
                assert_true(result.success, "Update should succeed")
                users_repo.collection.document.return_value.update.assert_called_once()
    
    def test_update_permission_denied(self, users_repo):
        """Test update with permission denied error."""
        updates = {'role': 'admin'}
        users_repo.collection.document.return_value.update.side_effect = PermissionDenied("Permission denied")
        
        with patch.object(users_repo, '_add_timestamps') as mock_add_timestamps:
            mock_add_timestamps.return_value = updates
            
            with assert_raises(PermissionError):
                users_repo.update("test_id", updates)
    
    def test_delete_success(self, users_repo):
        """Test successful user deletion."""
        result = users_repo.delete("test_user_id")
        
        assert_true(result.success, "Delete should succeed")
        assert_true(result.data, "Should return True")
        users_repo.collection.document.return_value.delete.assert_called_once()
    
    def test_delete_permission_denied(self, users_repo):
        """Test delete with permission denied error."""
        users_repo.collection.document.return_value.delete.side_effect = PermissionDenied("Permission denied")
        
        with assert_raises(PermissionError):
            users_repo.delete("test_id")
    
    def test_get_by_username_success(self, users_repo, sample_user):
        """Test successful get by username."""
        mock_doc = Mock()
        mock_doc.id = "test_user_id"
        mock_doc.to_dict.return_value = sample_user.to_dict()
        
        # Fix the mock chain
        stream_mock = Mock()
        stream_mock.return_value = [mock_doc]
        limit_mock = Mock()
        limit_mock.stream = stream_mock
        where_mock = Mock()
        where_mock.limit.return_value = limit_mock
        users_repo.collection.where.return_value = where_mock
        
        with patch.object(create_user, '__call__', return_value=sample_user) as mock_create_user:
            result = users_repo.get_by_username("testuser")
            
            assert_true(result.success, "Get by username should succeed")
            assert_is_not_none(result.data, "Should return user")
            assert_equals(result.data.id, "test_user_id", "Should set document ID")
    
    def test_get_by_username_not_found(self, users_repo):
        """Test get by username when user doesn't exist."""
        # Fix the mock chain
        stream_mock = Mock()
        stream_mock.return_value = []
        limit_mock = Mock()
        limit_mock.stream = stream_mock
        where_mock = Mock()
        where_mock.limit.return_value = limit_mock
        users_repo.collection.where.return_value = where_mock
        
        result = users_repo.get_by_username("nonexistent_user")
        
        assert_false(result.success, "Get by username should fail")
        assert_equals(result.error, "User not found", "Should return not found error")
        assert_equals(result.error_code, "NOT_FOUND", "Should return correct error code")
    
    def test_get_by_username_permission_denied(self, users_repo):
        """Test get by username with permission denied error."""
        # Fix the mock chain
        stream_mock = Mock()
        stream_mock.side_effect = PermissionDenied("Permission denied")
        limit_mock = Mock()
        limit_mock.stream = stream_mock
        where_mock = Mock()
        where_mock.limit.return_value = limit_mock
        users_repo.collection.where.return_value = where_mock
        
        with assert_raises(PermissionError):
            users_repo.get_by_username("testuser")
    
    def test_authenticate_user_success(self, users_repo, sample_user):
        """Test successful user authentication."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            with patch.object(users_repo, 'clear_failed_attempts') as mock_clear_attempts:
                mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
                
                result = users_repo.authenticate_user("testuser", "hashed_password_123")
                
                assert_true(result.success, "Authentication should succeed")
                assert_equals(result.data, sample_user, "Should return user")
                mock_clear_attempts.assert_called_once_with(sample_user.user_id)
    
    def test_authenticate_user_not_found(self, users_repo):
        """Test authentication with non-existent user."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.authenticate_user("nonexistent_user", "password")
            
            assert_false(result.success, "Authentication should fail")
            assert_equals(result.error, "User not found", "Should return not found error")
            assert_equals(result.error_code, "USER_NOT_FOUND", "Should return correct error code")
    
    def test_authenticate_user_locked(self, users_repo, sample_user):
        """Test authentication with locked user."""
        sample_user.locked_until = int(time.time() * 1000) + 3600000  # Locked for 1 hour
        
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
            
            result = users_repo.authenticate_user("testuser", "hashed_password_123")
            
            assert_false(result.success, "Authentication should fail")
            assert_equals(result.error, "Account locked", "Should return locked error")
            assert_equals(result.error_code, "ACCOUNT_LOCKED", "Should return correct error code")
    
    def test_authenticate_user_invalid_password(self, users_repo, sample_user):
        """Test authentication with invalid password."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            with patch.object(users_repo, 'increment_failed_attempts') as mock_increment_attempts:
                mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
                
                result = users_repo.authenticate_user("testuser", "wrong_password")
                
                assert_false(result.success, "Authentication should fail")
                assert_equals(result.error, "Invalid credentials", "Should return invalid credentials error")
                assert_equals(result.error_code, "INVALID_CREDENTIALS", "Should return correct error code")
                mock_increment_attempts.assert_called_once_with(sample_user.user_id)
    
    def test_update_last_login_success(self, users_repo):
        """Test successful last login update."""
        with patch.object(users_repo, 'update') as mock_update:
            mock_update.return_value = OperationResult(success=True, data=None)
            
            result = users_repo.update_last_login("test_user_id")
            
            assert_true(result.success, "Update last login should succeed")
            mock_update.assert_called_once()
    
    def test_increment_failed_attempts_success(self, users_repo, sample_user):
        """Test successful failed attempts increment."""
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            with patch.object(users_repo, 'update') as mock_update:
                mock_get_by_id.return_value = OperationResult(success=True, data=sample_user)
                mock_update.return_value = OperationResult(success=True, data=None)
                
                result = users_repo.increment_failed_attempts("test_user_id")
                
                assert_true(result.success, "Increment failed attempts should succeed")
                mock_update.assert_called_once_with("test_user_id", {'failed_attempts': sample_user.failed_attempts + 1})
    
    def test_increment_failed_attempts_user_not_found(self, users_repo):
        """Test increment failed attempts with non-existent user."""
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            mock_get_by_id.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.increment_failed_attempts("nonexistent_user_id")
            
            assert_false(result.success, "Increment should fail")
            assert_equals(result.error, "User not found", "Should return not found error")
    
    def test_clear_failed_attempts_success(self, users_repo):
        """Test successful failed attempts clearing."""
        with patch.object(users_repo, 'update') as mock_update:
            mock_update.return_value = OperationResult(success=True, data=None)
            
            result = users_repo.clear_failed_attempts("test_user_id")
            
            assert_true(result.success, "Clear failed attempts should succeed")
            mock_update.assert_called_once_with("test_user_id", {'failed_attempts': 0})
    
    def test_lock_user_success(self, users_repo):
        """Test successful user locking."""
        lock_until = int(time.time() * 1000) + 3600000
        
        with patch.object(users_repo, 'update') as mock_update:
            mock_update.return_value = OperationResult(success=True, data=None)
            
            result = users_repo.lock_user("test_user_id", lock_until)
            
            assert_true(result.success, "Lock user should succeed")
            # Check that update was called with the correct user_id and that locked_until is set
            mock_update.assert_called_once()
            call_args = mock_update.call_args
            assert_equals(call_args[0][0], "test_user_id", "Should call update with correct user_id")
            assert 'locked_until' in call_args[0][1], "Should include locked_until in updates"
    
    def test_update_password_success(self, users_repo, sample_user):
        """Test successful password update."""
        new_password_hash = "new_hashed_password"
        new_salt = "new_salt"
        algorithm_params = {"algorithm": "argon2id", "memory": 64}
        
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            with patch.object(users_repo, 'update') as mock_update:
                mock_get_by_id.return_value = OperationResult(success=True, data=sample_user)
                mock_update.return_value = OperationResult(success=True, data=None)
                
                result = users_repo.update_password("test_user_id", new_password_hash, new_salt, algorithm_params)
                
                assert_true(result.success, "Update password should succeed")
                # The method calls update twice - once for password history and once for the main update
                assert_equals(mock_update.call_count, 2, "Should call update twice")
    
    def test_update_password_user_not_found(self, users_repo):
        """Test password update with non-existent user."""
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            mock_get_by_id.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.update_password("nonexistent_user_id", "new_hash", "new_salt")
            
            assert_false(result.success, "Update password should fail")
            assert_equals(result.error, "User not found", "Should return not found error")
    
    def test_list_users_by_role_success(self, users_repo, sample_user):
        """Test successful user listing by role."""
        options = QueryOptions(limit=10)
        
        mock_doc = Mock()
        mock_doc.id = "test_user_id"
        mock_doc.to_dict.return_value = sample_user.to_dict()
        
        with patch.object(users_repo, '_apply_query_options') as mock_apply_options:
            with patch.object(create_user, '__call__', return_value=sample_user) as mock_create_user:
                mock_apply_options.return_value.stream.return_value = [mock_doc]
                mock_create_user.return_value = sample_user
                
                result = users_repo.list_users_by_role("operator", options)
                
                assert_is_instance(result, PaginatedResult, "Should return PaginatedResult")
                assert_equals(len(result.items), 1, "Should return 1 user")
                assert_equals(result.items[0].id, "test_user_id", "Should set document ID")
    
    def test_list_users_by_role_permission_denied(self, users_repo):
        """Test list users by role with permission denied error."""
        options = QueryOptions(limit=10)
        
        with patch.object(users_repo, '_apply_query_options') as mock_apply_options:
            mock_apply_options.return_value.stream.side_effect = PermissionDenied("Permission denied")
            
            with assert_raises(PermissionError):
                users_repo.list_users_by_role("operator", options)
    
    # Legacy compatibility methods tests
    def test_create_user_legacy_success(self, users_repo):
        """Test legacy create_user method."""
        with patch.object(users_repo, 'create') as mock_create:
            mock_create.return_value = OperationResult(success=True, data="test_user_id")
            
            result = users_repo.create_user("testuser", "hashed_password", "salt", "operator")
            
            assert_equals(result, "test_user_id", "Should return user ID")
            mock_create.assert_called_once()
    
    def test_create_user_legacy_failure(self, users_repo):
        """Test legacy create_user method with failure."""
        with patch.object(users_repo, 'create') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = users_repo.create_user("testuser", "hashed_password", "salt", "operator")
            
            assert_is_none(result, "Should return None on failure")
    
    def test_get_user_by_id_legacy_success(self, users_repo, sample_user):
        """Test legacy get_user_by_id method."""
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            mock_get_by_id.return_value = OperationResult(success=True, data=sample_user)
            
            result = users_repo.get_user_by_id("test_user_id")
            
            assert_is_instance(result, dict, "Should return dict")
            assert_equals(result['username'], "testuser", "Should return correct username")
    
    def test_get_user_by_id_legacy_not_found(self, users_repo):
        """Test legacy get_user_by_id method with not found."""
        with patch.object(users_repo, 'get_by_id') as mock_get_by_id:
            mock_get_by_id.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.get_user_by_id("nonexistent_id")
            
            assert_is_none(result, "Should return None when not found")
    
    def test_get_user_by_username_legacy_success(self, users_repo, sample_user):
        """Test legacy get_user_by_username method."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
            
            result = users_repo.get_user_by_username("testuser")
            
            assert_is_instance(result, dict, "Should return dict")
            assert_equals(result['username'], "testuser", "Should return correct username")
    
    def test_update_user_legacy_success(self, users_repo):
        """Test legacy update_user method."""
        updates = {'role': 'admin'}
        
        with patch.object(users_repo, 'update') as mock_update:
            mock_update.return_value = OperationResult(success=True, data=None)
            
            result = users_repo.update_user("test_user_id", updates)
            
            assert_true(result, "Should return True on success")
            mock_update.assert_called_once_with("test_user_id", updates)
    
    def test_update_user_legacy_failure(self, users_repo):
        """Test legacy update_user method with failure."""
        updates = {'role': 'admin'}
        
        with patch.object(users_repo, 'update') as mock_update:
            mock_update.side_effect = Exception("Test error")
            
            result = users_repo.update_user("test_user_id", updates)
            
            assert_false(result, "Should return False on failure")
    
    def test_delete_user_legacy_success(self, users_repo, sample_user):
        """Test legacy delete_user method."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            with patch.object(users_repo, 'delete') as mock_delete:
                mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
                mock_delete.return_value = OperationResult(success=True, data=True)
                
                result = users_repo.delete_user("testuser")
                
                assert_true(result, "Should return True on success")
                mock_delete.assert_called_once_with(sample_user.user_id)
    
    def test_delete_user_legacy_not_found(self, users_repo):
        """Test legacy delete_user method with not found."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.delete_user("nonexistent_user")
            
            assert_false(result, "Should return False when user not found")
    
    def test_is_user_locked_legacy_success(self, users_repo, sample_user):
        """Test legacy is_user_locked method."""
        sample_user.locked_until = int(time.time() * 1000) + 3600000  # Locked
        
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=True, data=sample_user)
            
            result = users_repo.is_user_locked("testuser")
            
            assert_true(result, "Should return True for locked user")
    
    def test_is_user_locked_legacy_not_found(self, users_repo):
        """Test legacy is_user_locked method with not found."""
        with patch.object(users_repo, 'get_by_username') as mock_get_by_username:
            mock_get_by_username.return_value = OperationResult(success=False, error="User not found")
            
            result = users_repo.is_user_locked("nonexistent_user")
            
            assert_false(result, "Should return False when user not found")
