"""Tests for SessionsStore with contract-based validation."""

import pytest
import time
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

# Real server implementation and exceptions
from server.services.firestore.sessions_store import SessionsStore
from google.api_core.exceptions import PermissionDenied

# Contract testing imports
from tests.contracts.base import SessionsStoreProtocol
from tests.contracts.firestore import ContractValidator
from tests.utils.business_rules import BusinessRules
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises
from tests.utils.mocks.firestore import (
    attach_collection,
    make_doc,
    set_where_chain,
    set_document_get,
)


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestSessionsStore:
    """Test cases for SessionsStore."""
    
    @pytest.fixture
    def mock_client(self, fs_client, fs_collection):
        """Create mock Firestore client using helpers and attach 'sessions' collection."""
        attach_collection(fs_client, 'sessions', fs_collection)
        return fs_client
    
    @pytest.fixture
    def sessions_store(self, mock_client):
        """Create SessionsStore instance."""
        return SessionsStore(mock_client)
    
    @pytest.fixture
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    @pytest.fixture
    def sample_request_info(self):
        """Create sample request info for testing."""
        return {
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        }

    @pytest.fixture
    def valid_session_data(self) -> Dict[str, Any]:
        """Provide valid session data for testing."""
        return {
            'session_id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'username': 'testuser',
            'role': 'operator',
            'tenant_id': 'a1b2c3d4-e5f6-4a5b-8c9d-1e2f3a4b5c6d',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'created_at_ms': int(time.time() * 1000),
            'expires_at_ms': int(time.time() * 1000) + 1800000,  # 30 minutes
            'is_active': True
        }
    
    def test_init(self, mock_client):
        """Test store initialization."""
        store = SessionsStore(mock_client)
        assert store.client == mock_client
        assert store.collection == mock_client.collection('sessions')
    
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
            assert_equals(call_args['tenant_id'], "f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c", "Should set tenant_id")
    
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        }
        
        set_document_get(
            sessions_store.collection,
            'test_session_id',
            exists=True,
            data=session_data,
        )
        
        result = sessions_store.get_session('test_session_id')
        
        assert_is_not_none(result, "Should return session data")
        assert_equals(result['session_id'], 'test_session_id', "Should return correct session ID")
        assert_equals(result['id'], 'test_session_id', "Should set document ID")
    
    def test_get_session_not_found(self, sessions_store):
        """Test session retrieval when document doesn't exist."""
        set_document_get(
            sessions_store.collection,
            'nonexistent_session_id',
            exists=False,
        )
        
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
        
        set_document_get(
            sessions_store.collection,
            'test_session_id',
            exists=True,
            data=session_data,
        )
        
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
        mock_doc1 = make_doc('session1', {
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        })
        mock_doc2 = make_doc('session2', {
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        })
        mock_doc3 = make_doc('session3', {
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        })
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id')],
            stream_docs=[mock_doc1, mock_doc2, mock_doc3],
        )
        
        result = sessions_store.invalidate_user_sessions('test_user_id')
        
        assert_equals(result, 3, "Should return count of invalidated sessions")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_called_once()
        mock_doc3.reference.delete.assert_called_once()
    
    def test_invalidate_user_sessions_with_exclusion(self, sessions_store):
        """Test user sessions invalidation with session exclusion."""
        # Create mock documents for user sessions
        mock_doc1 = make_doc('session1', {})
        mock_doc2 = make_doc('session2', {})
        mock_doc3 = make_doc('session3', {})
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id')],
            stream_docs=[mock_doc1, mock_doc2, mock_doc3],
        )
        
        result = sessions_store.invalidate_user_sessions('test_user_id', exclude_session_id='session2')
        
        assert_equals(result, 2, "Should return count of invalidated sessions (excluding session2)")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_not_called()  # Should be excluded
        mock_doc3.reference.delete.assert_called_once()
    
    def test_invalidate_user_sessions_permission_denied(self, sessions_store):
        """Test user sessions invalidation with permission denied error."""
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id')],
            side_effect=PermissionDenied("Permission denied"),
        )
        
        result = sessions_store.invalidate_user_sessions('test_user_id')
        
        assert_equals(result, 0, "Should return 0 on permission denied")
    
    def test_invalidate_user_sessions_exception(self, sessions_store):
        """Test user sessions invalidation with general exception."""
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id')],
            side_effect=Exception("Test error"),
        )
        
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
        mock_doc1 = make_doc('expired_session1', {
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        })
        
        mock_doc2 = make_doc('expired_session2', {
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        })
        set_where_chain(
            sessions_store.collection,
            filters=[('expires_at', '<=', current_time)],
            stream_docs=[mock_doc1, mock_doc2],
        )
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 2, "Should return count of cleaned sessions")
        mock_doc1.reference.delete.assert_called_once()
        mock_doc2.reference.delete.assert_called_once()
    
    def test_cleanup_expired_sessions_no_expired(self, sessions_store):
        """Test expired sessions cleanup with no expired sessions."""
        set_where_chain(
            sessions_store.collection,
            filters=[('expires_at', '<=', int(time.time() * 1000))],
            stream_docs=[],
        )
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 0, "Should return 0 when no expired sessions")
    
    def test_cleanup_expired_sessions_permission_denied(self, sessions_store):
        """Test expired sessions cleanup with permission denied error."""
        set_where_chain(
            sessions_store.collection,
            filters=[('expires_at', '<=', int(time.time() * 1000))],
            side_effect=PermissionDenied("Permission denied"),
        )
        
        result = sessions_store.cleanup_expired_sessions()
        
        assert_equals(result, 0, "Should return 0 on permission denied")
    
    def test_cleanup_expired_sessions_exception(self, sessions_store):
        """Test expired sessions cleanup with general exception."""
        set_where_chain(
            sessions_store.collection,
            filters=[('expires_at', '<=', int(time.time() * 1000))],
            side_effect=Exception("Test error"),
        )
        
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
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
            'tenant_id': 'f7a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b1c'
        }
        
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id'), ('expires_at', '>', future_time)],
            stream_docs=[mock_doc1, mock_doc2, mock_doc3],
        )
        
        result = sessions_store.get_active_sessions_count('test_user_id')
        
        assert_equals(result, 3, "Should return count of active sessions")
    
    def test_get_active_sessions_count_no_sessions(self, sessions_store):
        """Test active sessions count with no active sessions."""
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id'), ('expires_at', '>', int(time.time() * 1000))],
            stream_docs=[],
        )
        
        result = sessions_store.get_active_sessions_count('test_user_id')
        
        assert_equals(result, 0, "Should return 0 when no active sessions")
    
    def test_get_active_sessions_count_exception(self, sessions_store):
        """Test active sessions count with exception."""
        set_where_chain(
            sessions_store.collection,
            filters=[('user_id', '==', 'test_user_id'), ('expires_at', '>', int(time.time() * 1000))],
            side_effect=Exception("Test error"),
        )
        
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

    def test_contract_validation_create_session(self, sessions_store, contract_validator, business_rules, valid_session_data):
        """Test contract validation for session creation."""
        # Pre-validate session data against business rules
        session_result = business_rules.session_policy_check(
            user_id=valid_session_data['user_id'],
            tenant_id=valid_session_data['tenant_id'],
            role=valid_session_data['role']
        )
        assert_true(session_result['valid'], f"Session policy validation failed: {session_result['violations']}")

        # Validate session data structure against contract
        validation_result = contract_validator.validate_create_operation(
            valid_session_data,
            'session',
            tenant_id=valid_session_data['tenant_id'],
            user_id=valid_session_data['user_id']
        )
        assert_true(validation_result.valid, f"Contract validation failed: {validation_result.violations}")

    def test_contract_violation_invalid_session_id(self, contract_validator, valid_session_data):
        """Test contract violation with invalid session ID."""
        invalid_data = valid_session_data.copy()
        invalid_data['session_id'] = 'invalid'  # Too short for session ID requirements

        validation_result = contract_validator.validate_create_operation(
            invalid_data,
            'session',
            tenant_id=valid_session_data['tenant_id'],
            user_id=valid_session_data['user_id']
        )

        assert_false(validation_result.valid, "Invalid session data should fail validation")
        assert_true(len(validation_result.violations) > 0, "Should have validation violations")

    def test_business_rules_session_validation(self, business_rules, valid_session_data):
        """Test business rules validation for sessions."""
        # Test valid session
        result = business_rules.session_policy_check(
            user_id=valid_session_data['user_id'],
            tenant_id=valid_session_data['tenant_id'],
            role=valid_session_data['role']
        )

        assert_true(result['valid'], f"Session policy validation failed: {result['violations']}")

        # Test session without tenant (should still be valid but flagged)
        result_no_tenant = business_rules.session_policy_check(
            user_id=valid_session_data['user_id'],
            tenant_id=None,
            role=valid_session_data['role']
        )

        assert_true(result_no_tenant['valid'], "Session without tenant should be valid")

    def test_query_contract_validation(self, sessions_store, contract_validator, valid_session_data):
        """Test contract validation for query operations."""
        from tests.contracts.base import QueryOptions

        tenant_id = valid_session_data['tenant_id']
        user_id = valid_session_data['user_id']

        # Validate query filters against contract
        query_options = QueryOptions(
            filters={
                'tenant_id': tenant_id,
                'user_id': user_id,
                'is_active': True
            },
            limit=100
        )

        # Should validate successfully
        validation_result = contract_validator.validate_query_operation(
            query_options, 'session', tenant_id=tenant_id, user_id=user_id
        )
        assert_true(validation_result.valid, f"Valid query should pass validation: {validation_result.violations}")

        # Test query without tenant isolation (should violate contract)
        invalid_options = QueryOptions(
            filters={
                'user_id': user_id
                # Missing tenant_id
            },
            limit=100
        )

        invalid_result = contract_validator.validate_query_operation(
            invalid_options, 'session', tenant_id=tenant_id, user_id=user_id
        )
        assert_false(invalid_result.valid, "Query without tenant isolation should fail validation")

    def test_business_rules_session_creation_policy(self, business_rules, valid_session_data, sample_request_info):
        """Test business rules enforcement for session creation."""
        # Test valid session creation
        result = business_rules.session_policy_check(
            session_id=valid_session_data['session_id'],
            user_id=valid_session_data['user_id'],
            created_at_ms=valid_session_data['created_at_ms'],
            expires_at_ms=valid_session_data['expires_at_ms'],
            tenant_id=valid_session_data['tenant_id'],
            role=valid_session_data['role']
        )
        assert_true(result['valid'], f"Valid session should pass policy check: {result['violations']}")
        assert_true(result['has_required_fields'], "Should have all required fields")
        assert_true(result['timeout_valid'], "Should have valid timeout")

        # Test session with invalid timeout (too short)
        invalid_timeout_data = valid_session_data.copy()
        invalid_timeout_data['expires_at_ms'] = valid_session_data['created_at_ms'] + (15 * 60 * 1000)  # 15 minutes

        result = business_rules.session_policy_check(
            session_id=invalid_timeout_data['session_id'],
            user_id=invalid_timeout_data['user_id'],
            created_at_ms=invalid_timeout_data['created_at_ms'],
            expires_at_ms=invalid_timeout_data['expires_at_ms']
        )
        assert_false(result['valid'], "Session with too short timeout should fail")
        assert_true(any("timeout too short" in violation.lower() for violation in result['violations']),
                   "Should mention timeout issue")

        # Test session with invalid timeout (too long)
        invalid_timeout_data['expires_at_ms'] = valid_session_data['created_at_ms'] + (10 * 60 * 60 * 1000)  # 10 hours

        result = business_rules.session_policy_check(
            session_id=invalid_timeout_data['session_id'],
            user_id=invalid_timeout_data['user_id'],
            created_at_ms=invalid_timeout_data['created_at_ms'],
            expires_at_ms=invalid_timeout_data['expires_at_ms']
        )
        assert_false(result['valid'], "Session with too long timeout should fail")
        assert_true(any("timeout too long" in violation.lower() for violation in result['violations']),
                   "Should mention timeout issue")

    def test_business_rules_session_fingerprint_integrity(self, business_rules, valid_session_data, sample_request_info):
        """Test session fingerprint integrity validation."""
        # Test valid fingerprint
        ip_address = sample_request_info['ip_address']
        user_agent = sample_request_info['user_agent']

        # Calculate expected fingerprint
        import hashlib
        fingerprint_data = f"{ip_address}:{user_agent}"
        expected_fingerprint = f"fp_{hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]}"

        # Test fingerprint matches what store would generate
        result = business_rules.data_integrity_check({
            'fingerprint': expected_fingerprint,
            'ip_address': ip_address,
            'user_agent': user_agent
        })
        assert_true(result['valid'], "Valid fingerprint should pass integrity check")

        # Test tampered fingerprint
        tampered_data = {
            'fingerprint': 'fp_tamperedfingerprint',
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        result = business_rules.data_integrity_check(tampered_data)
        assert_false(result['valid'], "Tampered fingerprint should fail integrity check")

    def test_business_rules_concurrent_session_limits(self, business_rules, valid_session_data):
        """Test business rules for concurrent session limits."""
        user_id = valid_session_data['user_id']

        # Test normal concurrent sessions (within limits)
        sessions = [valid_session_data.copy() for _ in range(3)]
        for i, session in enumerate(sessions):
            session['session_id'] = f"session_{i}"

        # Rate limiting should allow normal usage patterns
        for session in sessions:
            rate_result = business_rules.rate_limit_check(
                requests=[session['created_at_ms']],
                time_window_ms=60 * 60 * 1000,  # 1 hour
                max_requests=10
            )
            assert_true(rate_result['allowed'], f"Normal session creation should be allowed: {session['session_id']}")

        # Test excessive concurrent session creation (potential abuse)
        excessive_requests = list(range(valid_session_data['created_at_ms'],
                                       valid_session_data['created_at_ms'] + (5 * 60 * 1000),  # 5 minutes
                                       10 * 1000))  # Every 10 seconds

        rate_result = business_rules.rate_limit_check(
            requests=excessive_requests,
            time_window_ms=5 * 60 * 1000,  # 5 minutes
            max_requests=3
        )
        assert_false(rate_result['allowed'], "Excessive session creation should be rate limited")
        assert_true(rate_result['request_count'] > rate_result['max_requests'],
                   "Should detect excessive requests")

    def test_business_rules_session_tenant_isolation(self, business_rules, valid_session_data):
        """Test tenant isolation enforcement for sessions."""
        # Test valid tenant isolation
        result = business_rules.tenant_isolation_check(
            tenant_id=valid_session_data['tenant_id'],
            resource_tenant_id=valid_session_data['tenant_id']
        )
        assert_true(result['valid'], "Same tenant should pass isolation check")
        assert_true(result['format_valid'], "Tenant ID format should be valid")

        # Test tenant isolation violation
        result = business_rules.tenant_isolation_check(
            tenant_id=valid_session_data['tenant_id'],
            resource_tenant_id='different_tenant'
        )
        assert_false(result['valid'], "Different tenant should fail isolation check")
        assert_true(any("violation" in violation.lower() for violation in result['violations']),
                   "Should mention isolation violation")

        # Test invalid tenant format
        result = business_rules.tenant_isolation_check(
            tenant_id='invalid_tenant',
            resource_tenant_id=valid_session_data['tenant_id']
        )
        assert_false(result['valid'], "Invalid tenant format should fail")
        assert_false(result['format_valid'], "Should detect invalid format")

    def test_business_rules_session_audit_trail(self, business_rules, valid_session_data):
        """Test audit trail requirements for session operations."""
        # Test session creation audit requirement
        result = business_rules.audit_trail_check(
            operation='create_session',
            user_id=valid_session_data['user_id'],
            tenant_id=valid_session_data['tenant_id']
        )
        assert_true(result['valid'], "Session creation should require audit")
        assert_true(result['audit_required'], "Session creation should be auditable")

        # Test session invalidation audit requirement
        result = business_rules.audit_trail_check(
            operation='delete_session',
            user_id=valid_session_data['user_id'],
            tenant_id=valid_session_data['tenant_id']
        )
        assert_true(result['valid'], "Session invalidation should require audit")
        assert_true(result['audit_required'], "Session invalidation should be auditable")

        # Test audit trail violation (missing tenant for sensitive operation)
        result = business_rules.audit_trail_check(
            operation='create_session',
            user_id=valid_session_data['user_id'],
            tenant_id=None
        )
        assert_false(result['valid'], "Session creation without tenant should fail")
        assert_true(any("tenant" in violation.lower() for violation in result['violations']),
                   "Should require tenant for session creation")

    def test_business_rules_session_lifecycle_integrity(self, business_rules, valid_session_data):
        """Test session lifecycle integrity rules."""
        # Test complete session lifecycle data integrity
        session_lifecycle = {
            'session_id': valid_session_data['session_id'],
            'user_id': valid_session_data['user_id'],
            'created_at_ms': valid_session_data['created_at_ms'],
            'expires_at_ms': valid_session_data['expires_at_ms'],
            'last_access': valid_session_data['created_at_ms'] + (10 * 60 * 1000),  # 10 minutes later
            'tenant_id': valid_session_data['tenant_id'],
            'role': valid_session_data['role']
        }

        # Test data integrity
        result = business_rules.data_integrity_check(session_lifecycle)
        assert_true(result['valid'], "Valid session lifecycle should pass integrity check")

        # Test session expiration rules
        current_time = valid_session_data['expires_at_ms'] + (60 * 60 * 1000)  # 1 hour after expiry
        ttl_result = business_rules.ttl_enforce(
            created_at_ms=valid_session_data['created_at_ms'],
            ttl_days=1,  # 1 day TTL
            current_time_ms=current_time,
            expires_at_ms=valid_session_data['expires_at_ms']
        )
        assert_true(ttl_result['is_expired'], "Session should be detected as expired")

        # Test valid session (not expired)
        current_time = valid_session_data['expires_at_ms'] - (60 * 60 * 1000)  # 1 hour before expiry
        ttl_result = business_rules.ttl_enforce(
            created_at_ms=valid_session_data['created_at_ms'],
            ttl_days=1,
            current_time_ms=current_time
        )
        assert_false(ttl_result['is_expired'], "Session should not be expired yet")

    def test_enhanced_contract_validation_with_business_rules(self, sessions_store, contract_validator,
                                                             business_rules, valid_session_data, sample_request_info):
        """Test enhanced contract validation combined with business rules."""
        # Pre-validate session creation with business rules
        policy_result = business_rules.session_policy_check(
            session_id=valid_session_data['session_id'],
            user_id=valid_session_data['user_id'],
            created_at_ms=valid_session_data['created_at_ms'],
            expires_at_ms=valid_session_data['expires_at_ms'],
            tenant_id=valid_session_data['tenant_id'],
            role=valid_session_data['role']
        )
        assert_true(policy_result['valid'], f"Business rules validation failed: {policy_result['violations']}")

        # Test tenant isolation for session
        isolation_result = business_rules.tenant_isolation_check(
            tenant_id=valid_session_data['tenant_id'],
            resource_tenant_id=valid_session_data['tenant_id']
        )
        assert_true(isolation_result['valid'], f"Tenant isolation failed: {isolation_result['violations']}")

        # Validate session data against contract
        validation_result = contract_validator.validate_create_operation(
            valid_session_data,
            'session',
            tenant_id=valid_session_data['tenant_id'],
            user_id=valid_session_data['user_id']
        )
        assert_true(validation_result.valid, f"Contract validation failed: {validation_result.violations}")

        # Test query operations with enhanced validation
        from tests.contracts.base import QueryOptions

        query_options = QueryOptions(
            filters={
                'tenant_id': valid_session_data['tenant_id'],
                'user_id': valid_session_data['user_id'],
                'expires_at_ms': ('>', int(time.time() * 1000))
            },
            limit=10
        )

        query_validation = contract_validator.validate_query_operation(
            query_options, 'session', tenant_id=valid_session_data['tenant_id'], user_id=valid_session_data['user_id']
        )
        assert_true(query_validation.valid, f"Query validation failed: {query_validation.violations}")

        # Test invalid query (missing tenant isolation)
        invalid_query = QueryOptions(
            filters={
                'user_id': valid_session_data['user_id']
                # Missing tenant_id
            },
            limit=10
        )

        invalid_query_validation = contract_validator.validate_query_operation(
            invalid_query, 'session', tenant_id=valid_session_data['tenant_id'], user_id=valid_session_data['user_id']
        )
        assert_false(invalid_query_validation.valid, "Query without tenant isolation should fail")

    def test_business_rules_comprehensive_session_validation(self, business_rules, valid_session_data):
        """Comprehensive test of all business rules for session operations."""
        # Test auth validation for session user
        auth_result = business_rules.auth_check(
            user_id=valid_session_data['user_id'],
            session_id=valid_session_data['session_id'],
            tenant_id=valid_session_data['tenant_id']
        )
        assert_true(auth_result['valid'], f"Auth validation failed: {auth_result['violations']}")

        # Test password policy (though not directly applicable to sessions, test the method)
        password_result = business_rules.password_policy_check("TempPassword123!")
        assert_true(password_result['valid'], "Password policy should validate test password")

        # Test rate limiting for session operations
        session_operations = [
            valid_session_data['created_at_ms'] + i * 10000 for i in range(5)  # 5 operations over time
        ]
        rate_limit_result = business_rules.rate_limit_check(
            requests=session_operations,
            time_window_ms=60 * 1000,  # 1 minute
            max_requests=10
        )
        assert_true(rate_limit_result['allowed'], "Normal session operations should be allowed")

        # Test data integrity across session fields
        session_for_integrity = valid_session_data.copy()
        integrity_result = business_rules.data_integrity_check(session_for_integrity)
        assert_true(integrity_result['valid'], "Session data should pass integrity check")

        # Test TTL enforcement
        ttl_result = business_rules.ttl_enforce(
            created_at_ms=valid_session_data['created_at_ms'],
            ttl_days=1
        )
        assert_true(ttl_result['valid'], "Session TTL should be valid")
        assert_false(ttl_result['is_expired'], "New session should not be expired")
