"""Tests for SessionsStore."""

import pytest
import time
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    SessionsRepository as SessionsStore, FirestoreError, PermissionError,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestSessionsStore:
    """Test cases for SessionsStore."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def sessions_store(self, mock_client):
        """Create SessionsStore instance."""
        return SessionsStore(mock_client)
    
    @pytest.fixture
    def sample_request_info(self):
        """Create sample request info for testing."""
        return {
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'tenant_id': 'test_tenant'
        }
    
    def test_init(self, mock_client):
        """Test store initialization."""
        store = SessionsStore(mock_client)
        assert store.client == mock_client
        assert store.collection == mock_client.collection.return_value
    
    def test_create_session_success(self, sessions_store, sample_request_info):
        """Test successful session creation."""
        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = "test_session_token"
            
            result = sessions_store.create_session(
                user_id="test_user_id",
                username="testuser",
                role="operator",
                expires_in_seconds=1800,
                request_info=sample_request_info
            )
            
            assert_is_not_none(result, "Should return session ID")
            assert_true(result.startswith("sess_"), "Session ID should start with 'sess_'")
            sessions_store.collection.document.return_value.set.assert_called_once()
    
    def test_create_session_default_expiry(self, sessions_store, sample_request_info):
        """Test session creation with default expiry."""
        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = "test_session_token"
            
            result = sessions_store.create_session(
                user_id="test_user_id",
                username="testuser",
                role="operator",
                request_info=sample_request_info
            )
            
            assert_is_not_none(result, "Should return session ID")
            # Verify the session document was created with correct structure
            call_args = sessions_store.collection.document.return_value.set.call_args[0][0]
            assert_equals(call_args['username'], "testuser", "Should set username")
            assert_equals(call_args['role'], "operator", "Should set role")
            assert_equals(call_args['tenant_id'], "test_tenant", "Should set tenant_id")
    
    def test_create_session_no_request_info(self, sessions_store):
        """Test session creation without request info."""
        with patch('secrets.token_urlsafe') as mock_token:
            mock_token.return_value = "test_session_token"
            
            result = sessions_store.create_session(
                user_id="test_user_id",
                username="testuser",
                role="operator"
            )
            
            assert_is_not_none(result, "Should return session ID")
            # Verify default values are used
            call_args = sessions_store.collection.document.return_value.set.call_args[0][0]
            assert_equals(call_args['ip_address'], 'unknown', "Should use default IP")
            assert_equals(call_args['user_agent'], 'unknown', "Should use default user agent")
    
    def test_create_session_permission_denied(self, sessions_store, sample_request_info):
        """Test session creation with permission denied error."""
        sessions_store.collection.document.return_value.set.side_effect = PermissionDenied("Permission denied")
        
        result = sessions_store.create_session(
            user_id="test_user_id",
            username="testuser",
            role="operator",
            request_info=sample_request_info
        )
        
        assert_is_none(result, "Should return None on permission denied")
    
    def test_create_session_exception(self, sessions_store, sample_request_info):
        """Test session creation with general exception."""
        sessions_store.collection.document.return_value.set.side_effect = Exception("Test error")
        
        result = sessions_store.create_session(
            user_id="test_user_id",
            username="testuser",
            role="operator",
            request_info=sample_request_info
        )
        
        assert_is_none(result, "Should return None on exception")
    
    def test_get_session_success(self, sessions_store):
        """Test successful session retrieval."""
        current_time = int(time.time() * 1000)
        expires_at = current_time + 3600000  # 1 hour from now
        
        session_data = {
            'session_id': 'test_session_id',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': current_time,
            'expires_at': expires_at,
            'last_access': current_time,
            'fingerprint': 'fp_test_fingerprint',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'tenant_id': 'test_tenant'
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.id = 'test_session_id'
        mock_doc.to_dict.return_value = session_data
        
        sessions_store.collection.document.return_value.get.return_value = mock_doc
        
        result = sessions_store.get_session('test_session_id')
        
        assert_is_not_none(result, "Should return session data")
        assert_equals(result['session_id'], 'test_session_id', "Should return correct session ID")
        assert_equals(result['id'], 'test_session_id', "Should set document ID")
    
    def test_get_session_not_found(self, sessions_store):
        """Test session retrieval when document doesn't exist."""
        mock_doc = Mock()
        mock_doc.exists = False
        
        sessions_store.collection.document.return_value.get.return_value = mock_doc
        
        result = sessions_store.get_session('nonexistent_session_id')
        
        assert_is_none(result, "Should return None when session not found")
    
    def test_get_session_expired(self, sessions_store):
        """Test session retrieval when session is expired."""
        current_time = int(time.time() * 1000)
        expires_at = current_time - 3600000  # 1 hour ago (expired)
        
        session_data = {
            'session_id': 'test_session_id',
            'expires_at': expires_at
        }
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.id = 'test_session_id'
        mock_doc.to_dict.return_value = session_data
        
        sessions_store.collection.document.return_value.get.return_value = mock_doc
        
        result = sessions_store.get_session('test_session_id')
        
        assert_is_none(result, "Should return None for expired session")
    
    def test_get_session_permission_denied(self, sessions_store):
        """Test session retrieval with permission denied error."""
        sessions_store.collection.document.return_value.get.side_effect = PermissionDenied("Permission denied")
        
        result = sessions_store.get_session('test_session_id')
        
        assert_is_none(result, "Should return None on permission denied")
    
    def test_get_session_exception(self, sessions_store):
        """Test session retrieval with general exception."""
        sessions_store.collection.document.return_value.get.side_effect = Exception("Test error")
        
        result = sessions_store.get_session('test_session_id')
        
        assert_is_none(result, "Should return None on exception")
    
    def test_update_session_access_success(self, sessions_store):
        """Test successful session access update."""
        result = sessions_store.update_session_access('test_session_id')
        
        assert_true(result, "Should return True on success")
        sessions_store.collection.document.return_value.update.assert_called_once()
    
    def test_update_session_access_permission_denied(self, sessions_store):
        """Test session access update with permission denied error."""
        sessions_store.collection.document.return_value.update.side_effect = PermissionDenied("Permission denied")
        
        result = sessions_store.update_session_access('test_session_id')
        
        assert_false(result, "Should return False on permission denied")
    
    def test_update_session_access_exception(self, sessions_store):
        """Test session access update with general exception."""
        sessions_store.collection.document.return_value.update.side_effect = Exception("Test error")
        
        result = sessions_store.update_session_access('test_session_id')
        
        assert_false(result, "Should return False on exception")
    
    def test_invalidate_session_success(self, sessions_store):
        """Test successful session invalidation."""
        result = sessions_store.invalidate_session('test_session_id')
        
        assert_true(result, "Should return True on success")
        sessions_store.collection.document.return_value.delete.assert_called_once()
    
    def test_invalidate_session_permission_denied(self, sessions_store):
        """Test session invalidation with permission denied error."""
        sessions_store.collection.document.return_value.delete.side_effect = PermissionDenied("Permission denied")
        
        result = sessions_store.invalidate_session('test_session_id')
        
        assert_false(result, "Should return False on permission denied")
    
    def test_invalidate_session_exception(self, sessions_store):
        """Test session invalidation with general exception."""
        sessions_store.collection.document.return_value.delete.side_effect = Exception("Test error")
        
        result = sessions_store.invalidate_session('test_session_id')
        
        assert_false(result, "Should return False on exception")
    
    def test_invalidate_user_sessions_success(self, sessions_store):
        """Test successful user sessions invalidation."""
        # Create mock documents for user sessions with proper session data
        mock_doc1 = Mock()
        mock_doc1.id = 'session1'
        mock_doc1.to_dict.return_value = {
            'session_id': 'session1',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': 1234567890000,
            'expires_at': 1234567890000 + 3600000,
            'last_access': 1234567890000,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        mock_doc1.reference.delete = Mock()
        
        mock_doc2 = Mock()
        mock_doc2.id = 'session2'
        mock_doc2.to_dict.return_value = {
            'session_id': 'session2',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': 1234567890000,
            'expires_at': 1234567890000 + 3600000,
            'last_access': 1234567890000,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        mock_doc2.reference.delete = Mock()
        
        mock_doc3 = Mock()
        mock_doc3.id = 'session3'
        mock_doc3.to_dict.return_value = {
            'session_id': 'session3',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': 1234567890000,
            'expires_at': 1234567890000 + 3600000,
            'last_access': 1234567890000,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        mock_doc3.reference.delete = Mock()
        
        query_mock = Mock()
        query_mock.stream.return_value = [mock_doc1, mock_doc2, mock_doc3]
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.invalidate_user_sessions('test_user_id')
        
        assert_equals(result, 3, "Should return count of invalidated sessions")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_called_once()
        mock_doc3.reference.delete.assert_called_once()
    
    def test_invalidate_user_sessions_with_exclusion(self, sessions_store):
        """Test user sessions invalidation with session exclusion."""
        # Create mock documents for user sessions
        mock_doc1 = Mock()
        mock_doc1.id = 'session1'
        mock_doc1.reference.delete = Mock()
        
        mock_doc2 = Mock()
        mock_doc2.id = 'session2'
        mock_doc2.reference.delete = Mock()
        
        mock_doc3 = Mock()
        mock_doc3.id = 'session3'
        mock_doc3.reference.delete = Mock()
        
        query_mock = Mock()
        query_mock.stream.return_value = [mock_doc1, mock_doc2, mock_doc3]
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.invalidate_user_sessions('test_user_id', exclude_session_id='session2')
        
        assert_equals(result, 2, "Should return count of invalidated sessions (excluding session2)")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_not_called()  # Should be excluded
        mock_doc3.reference.delete.assert_called_once()
    
    def test_invalidate_user_sessions_permission_denied(self, sessions_store):
        """Test user sessions invalidation with permission denied error."""
        query_mock = Mock()
        query_mock.stream.side_effect = PermissionDenied("Permission denied")
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.invalidate_user_sessions('test_user_id')
        
        assert_equals(result, 0, "Should return 0 on permission denied")
    
    def test_invalidate_user_sessions_exception(self, sessions_store):
        """Test user sessions invalidation with general exception."""
        query_mock = Mock()
        query_mock.stream.side_effect = Exception("Test error")
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.invalidate_user_sessions('test_user_id')
        
        assert_equals(result, 0, "Should return 0 on exception")
    
    def test_rotate_session_success(self, sessions_store, sample_request_info):
        """Test successful session rotation."""
        with patch.object(sessions_store, 'create_session') as mock_create:
            with patch.object(sessions_store, 'invalidate_session') as mock_invalidate:
                mock_create.return_value = 'new_session_id'
                
                result = sessions_store.rotate_session(
                    old_session_id='old_session_id',
                    user_id='test_user_id',
                    username='testuser',
                    role='operator',
                    expires_in_seconds=1800,
                    request_info=sample_request_info
                )
                
                assert_equals(result, 'new_session_id', "Should return new session ID")
                mock_create.assert_called_once()
                mock_invalidate.assert_called_once_with('old_session_id')
    
    def test_rotate_session_create_failure(self, sessions_store, sample_request_info):
        """Test session rotation when new session creation fails."""
        with patch.object(sessions_store, 'create_session') as mock_create:
            with patch.object(sessions_store, 'invalidate_session') as mock_invalidate:
                mock_create.return_value = None  # Creation failed
                
                result = sessions_store.rotate_session(
                    old_session_id='old_session_id',
                    user_id='test_user_id',
                    username='testuser',
                    role='operator',
                    request_info=sample_request_info
                )
                
                assert_is_none(result, "Should return None when creation fails")
                mock_invalidate.assert_not_called()  # Should not invalidate old session
    
    def test_rotate_session_exception(self, sessions_store, sample_request_info):
        """Test session rotation with general exception."""
        with patch.object(sessions_store, 'create_session') as mock_create:
            mock_create.side_effect = Exception("Test error")
            
            result = sessions_store.rotate_session(
                old_session_id='old_session_id',
                user_id='test_user_id',
                username='testuser',
                role='operator',
                request_info=sample_request_info
            )
            
            assert_is_none(result, "Should return None on exception")
    
    def test_cleanup_expired_sessions_success(self, sessions_store):
        """Test successful expired sessions cleanup."""
        current_time = int(time.time() * 1000)
        expired_time = current_time - 3600000  # 1 hour ago
        
        # Create mock expired session documents with proper session data
        mock_doc1 = Mock()
        mock_doc1.id = 'expired_session1'
        mock_doc1.to_dict.return_value = {
            'session_id': 'expired_session1',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': expired_time,
            'expires_at': expired_time,
            'last_access': expired_time,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        mock_doc1.reference.delete = Mock()
        
        mock_doc2 = Mock()
        mock_doc2.id = 'expired_session2'
        mock_doc2.to_dict.return_value = {
            'session_id': 'expired_session2',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': expired_time,
            'expires_at': expired_time,
            'last_access': expired_time,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        mock_doc2.reference.delete = Mock()
        
        query_mock = Mock()
        query_mock.stream.return_value = [mock_doc1, mock_doc2]
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 2, "Should return count of cleaned sessions")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_called_once()
    
    def test_cleanup_expired_sessions_no_expired(self, sessions_store):
        """Test expired sessions cleanup with no expired sessions."""
        query_mock = Mock()
        query_mock.stream.return_value = []  # No expired sessions
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 0, "Should return 0 when no expired sessions")
    
    def test_cleanup_expired_sessions_permission_denied(self, sessions_store):
        """Test expired sessions cleanup with permission denied error."""
        query_mock = Mock()
        query_mock.stream.side_effect = PermissionDenied("Permission denied")
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 0, "Should return 0 on permission denied")
    
    def test_cleanup_expired_sessions_exception(self, sessions_store):
        """Test expired sessions cleanup with general exception."""
        query_mock = Mock()
        query_mock.stream.side_effect = Exception("Test error")
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 0, "Should return 0 on exception")
    
    def test_get_active_sessions_count_success(self, sessions_store):
        """Test successful active sessions count retrieval."""
        current_time = int(time.time() * 1000)
        future_time = current_time + 3600000  # 1 hour from now
        
        # Create mock active session documents with proper session data
        mock_doc1 = Mock()
        mock_doc1.id = 'active_session1'
        mock_doc1.to_dict.return_value = {
            'session_id': 'active_session1',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': current_time,
            'expires_at': future_time,
            'last_access': current_time,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        
        mock_doc2 = Mock()
        mock_doc2.id = 'active_session2'
        mock_doc2.to_dict.return_value = {
            'session_id': 'active_session2',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': current_time,
            'expires_at': future_time,
            'last_access': current_time,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        
        mock_doc3 = Mock()
        mock_doc3.id = 'active_session3'
        mock_doc3.to_dict.return_value = {
            'session_id': 'active_session3',
            'user_id': 'test_user_id',
            'username': 'testuser',
            'role': 'operator',
            'created_at': current_time,
            'expires_at': future_time,
            'last_access': current_time,
            'fingerprint': 'fp_test',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'tenant_id': 'test_tenant'
        }
        
        query_mock = Mock()
        query_mock.where.return_value.where.return_value.stream.return_value = [mock_doc1, mock_doc2, mock_doc3]
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.get_active_sessions_count('test_user_id')
        
        assert_equals(result, 3, "Should return count of active sessions")
    
    def test_get_active_sessions_count_no_sessions(self, sessions_store):
        """Test active sessions count with no active sessions."""
        query_mock = Mock()
        query_mock.where.return_value.where.return_value.stream.return_value = []
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.get_active_sessions_count('test_user_id')
        
        assert_equals(result, 0, "Should return 0 when no active sessions")
    
    def test_get_active_sessions_count_exception(self, sessions_store):
        """Test active sessions count with exception."""
        query_mock = Mock()
        query_mock.where.return_value.where.return_value.stream.side_effect = Exception("Test error")
        sessions_store.collection.where.return_value = query_mock
        
        result = sessions_store.get_active_sessions_count('test_user_id')
        
        assert_equals(result, 0, "Should return 0 on exception")
    
    def test_create_fingerprint(self, sessions_store):
        """Test session fingerprint creation."""
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Test Browser)"
        
        result = sessions_store._create_fingerprint(ip_address, user_agent)
        
        assert_true(result.startswith("fp_"), "Fingerprint should start with 'fp_'")
        assert_equals(len(result), 19, "Fingerprint should be 19 characters (fp_ + 16 hex chars)")
        
        # Test that same input produces same fingerprint
        result2 = sessions_store._create_fingerprint(ip_address, user_agent)
        assert_equals(result, result2, "Same input should produce same fingerprint")
        
        # Test that different input produces different fingerprint
        result3 = sessions_store._create_fingerprint("192.168.1.101", user_agent)
        assert_not_equals(result, result3, "Different input should produce different fingerprint")
    
    def test_create_fingerprint_hash_calculation(self, sessions_store):
        """Test that fingerprint uses correct hash calculation."""
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Test Browser)"
        
        # Calculate expected hash manually
        fingerprint_data = f"{ip_address}:{user_agent}"
        expected_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        expected_fingerprint = f"fp_{expected_hash}"
        
        result = sessions_store._create_fingerprint(ip_address, user_agent)
        
        assert_equals(result, expected_fingerprint, "Should produce expected fingerprint")
