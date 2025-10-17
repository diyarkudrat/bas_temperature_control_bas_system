"""Tests for AuditLogStore."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from tests.unit.firestore.mock import (
    AuditRepository as AuditLogStore, FirestoreError, PermissionError,
    MockPermissionDenied as PermissionDenied, MockNotFound as NotFound
)
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestAuditLogStore:
    """Test cases for AuditLogStore."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Firestore client."""
        client = Mock()
        client.collection.return_value = Mock()
        return client
    
    @pytest.fixture
    def audit_store(self, mock_client):
        """Create AuditLogStore instance."""
        return AuditLogStore(mock_client)
    
    def test_init(self, mock_client):
        """Test store initialization."""
        store = AuditLogStore(mock_client)
        assert store.client == mock_client
        assert store.collection == mock_client.collection.return_value
    
    def test_log_event_success(self, audit_store):
        """Test successful event logging."""
        result = audit_store.log_event(
            event_type='LOGIN_SUCCESS',
            user_id='test_user_id',
            username='testuser',
            ip_address='192.168.1.100',
            user_agent='Mozilla/5.0 (Test Browser)',
            details={'session_id': 'test_session'},
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log event should succeed")
        audit_store.collection.add.assert_called_once()
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_SUCCESS', "Should set event type")
        assert_equals(call_args['user_id'], 'test_user_id', "Should set user ID")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
        assert_is_instance(call_args['timestamp_ms'], int, "Should set timestamp_ms")
        assert_true(call_args['utc_timestamp'].endswith('+00:00'), "Should set UTC timestamp")
    
    def test_log_event_minimal_data(self, audit_store):
        """Test event logging with minimal data."""
        result = audit_store.log_event(
            event_type='SYSTEM_STARTUP'
        )
        
        assert_true(result, "Log event should succeed with minimal data")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SYSTEM_STARTUP', "Should set event type")
        assert_is_none(call_args.get('user_id'), "Should not set user ID when not provided")
        assert_is_none(call_args.get('username'), "Should not set username when not provided")
        assert_equals(call_args.get('details', {}), {}, "Should set empty details dict")
    
    def test_log_event_with_custom_details(self, audit_store):
        """Test event logging with custom details."""
        custom_details = {
            'resource': '/api/sensitive-data',
            'action': 'READ',
            'result': 'DENIED',
            'reason': 'Insufficient permissions'
        }
        
        result = audit_store.log_event(
            event_type='PERMISSION_DENIED',
            username='testuser',
            ip_address='192.168.1.100',
            details=custom_details,
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log event should succeed")
        
        # Verify custom details are preserved
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['details'], custom_details, "Should preserve custom details")
    
    def test_log_event_permission_denied(self, audit_store):
        """Test event logging with permission denied error."""
        audit_store.collection.add.side_effect = PermissionDenied("Permission denied")
        
        result = audit_store.log_event(
            event_type='LOGIN_SUCCESS',
            username='testuser'
        )
        
        assert_false(result, "Log event should fail on permission denied")
    
    def test_log_event_exception(self, audit_store):
        """Test event logging with general exception."""
        audit_store.collection.add.side_effect = Exception("Test error")
        
        result = audit_store.log_event(
            event_type='LOGIN_SUCCESS',
            username='testuser'
        )
        
        assert_false(result, "Log event should fail on exception")
    
    def test_log_auth_success(self, audit_store):
        """Test successful authentication logging."""
        result = audit_store.log_auth_success(
            username='testuser',
            ip_address='192.168.1.100',
            session_id='test_session_id',
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log auth success should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_SUCCESS', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'test_session_id', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
    
    def test_log_auth_failure(self, audit_store):
        """Test failed authentication logging."""
        result = audit_store.log_auth_failure(
            username='testuser',
            ip_address='192.168.1.100',
            failure_reason='Invalid password',
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log auth failure should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_FAILURE', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['failure_reason'], 'Invalid password', "Should set failure reason in details")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
    
    def test_log_session_creation(self, audit_store):
        """Test session creation logging."""
        result = audit_store.log_session_creation(
            username='testuser',
            session_id='test_session_id',
            ip_address='192.168.1.100',
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log session creation should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_CREATED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'test_session_id', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
    
    def test_log_session_destruction(self, audit_store):
        """Test session destruction logging."""
        result = audit_store.log_session_destruction(
            session_id='test_session_id',
            username='testuser',
            ip_address='192.168.1.100',
            tenant_id='test_tenant'
        )
        
        assert_true(result, "Log session destruction should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_DESTROYED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'test_session_id', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
    
    def test_log_session_destruction_minimal_data(self, audit_store):
        """Test session destruction logging with minimal data."""
        result = audit_store.log_session_destruction(
            session_id='test_session_id'
        )
        
        assert_true(result, "Log session destruction should succeed with minimal data")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_DESTROYED', "Should set correct event type")
        assert_equals(call_args['details']['session_id'], 'test_session_id', "Should set session ID in details")
        assert_is_none(call_args.get('username'), "Should not set username when not provided")
        assert_is_none(call_args.get('ip_address'), "Should not set IP address when not provided")
    
    def test_log_permission_denied(self, audit_store):
        """Test permission denied logging."""
        result = audit_store.log_permission_denied(
            username='testuser',
            user_id='test_user_id',
            ip_address='192.168.1.100',
            resource='/api/sensitive-data',
            tenant_id='test_tenant',
            reason='INSUFFICIENT_PERMISSIONS'
        )
        
        assert_true(result, "Log permission denied should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'PERMISSION_DENIED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['user_id'], 'test_user_id', "Should set user ID")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['resource'], '/api/sensitive-data', "Should set resource in details")
        assert_equals(call_args['details']['reason'], 'INSUFFICIENT_PERMISSIONS', "Should set reason in details")
        assert_equals(call_args['tenant_id'], 'test_tenant', "Should set tenant ID")
    
    def test_log_permission_denied_default_reason(self, audit_store):
        """Test permission denied logging with default reason."""
        result = audit_store.log_permission_denied(
            username='testuser',
            ip_address='192.168.1.100',
            resource='/api/sensitive-data'
        )
        
        assert_true(result, "Log permission denied should succeed")
        
        # Verify default reason is used
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['details']['reason'], 'INSUFFICIENT_PERMISSIONS', "Should use default reason")
    
    def test_log_tenant_violation(self, audit_store):
        """Test tenant violation logging."""
        result = audit_store.log_tenant_violation(
            username='testuser',
            user_id='test_user_id',
            ip_address='192.168.1.100',
            attempted_tenant='tenant_b',
            allowed_tenant='tenant_a'
        )
        
        assert_true(result, "Log tenant violation should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'TENANT_VIOLATION', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['user_id'], 'test_user_id', "Should set user ID")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['attempted_tenant'], 'tenant_b', "Should set attempted tenant in details")
        assert_equals(call_args['details']['allowed_tenant'], 'tenant_a', "Should set allowed tenant in details")
        assert_equals(call_args['tenant_id'], 'tenant_b', "Should set attempted tenant as tenant_id")
    
    def test_query_events_by_user_success(self, audit_store):
        """Test successful query events by user."""
        audit_data = [
            {
                'event_type': 'LOGIN_SUCCESS',
                'user_id': 'test_user_id',
                'username': 'testuser',
                'timestamp_ms': int(time.time() * 1000),
                'details': {}
            },
            {
                'event_type': 'SESSION_CREATED',
                'user_id': 'test_user_id',
                'username': 'testuser',
                'timestamp_ms': int(time.time() * 1000) - 1000,
                'details': {}
            }
        ]
        
        mock_doc1 = Mock()
        mock_doc1.id = 'doc1'
        mock_doc1.to_dict.return_value = audit_data[0]
        
        mock_doc2 = Mock()
        mock_doc2.id = 'doc2'
        mock_doc2.to_dict.return_value = audit_data[1]
        
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc1, mock_doc2]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_user('test_user_id', 100)
        
        assert_equals(len(result), 2, "Should return 2 events")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['event_type'], 'LOGIN_SUCCESS', "Should return correct event type")
        assert_equals(result[1]['id'], 'doc2', "Should set document ID")
        assert_equals(result[1]['event_type'], 'SESSION_CREATED', "Should return correct event type")
    
    def test_query_events_by_user_permission_denied(self, audit_store):
        """Test query events by user with permission denied error."""
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_user('test_user_id', 100)
        
        assert_equals(result, [], "Should return empty list on permission denied")
    
    def test_query_events_by_user_exception(self, audit_store):
        """Test query events by user with general exception."""
        query_mock = Mock()
        query_mock.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = Exception("Test error")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_user('test_user_id', 100)
        
        assert_equals(result, [], "Should return empty list on exception")
    
    def test_query_events_by_type_success(self, audit_store):
        """Test successful query events by type."""
        audit_data = {
            'event_type': 'LOGIN_FAILURE',
            'username': 'testuser',
            'timestamp_ms': int(time.time() * 1000),
            'details': {'failure_reason': 'Invalid password'}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_type('LOGIN_FAILURE', 100)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['event_type'], 'LOGIN_FAILURE', "Should return correct event type")
        assert_equals(result[0]['details']['failure_reason'], 'Invalid password', "Should preserve details")
    
    def test_query_events_by_type_permission_denied(self, audit_store):
        """Test query events by type with permission denied error."""
        query_mock = Mock()
        query_mock.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_type('LOGIN_FAILURE', 100)
        
        assert_equals(result, [], "Should return empty list on permission denied")
    
    def test_query_recent_events_success(self, audit_store):
        """Test successful query recent events."""
        audit_data = {
            'event_type': 'SYSTEM_STARTUP',
            'timestamp_ms': int(time.time() * 1000),
            'details': {}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        query_mock = Mock()
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.order_by.return_value = query_mock
        
        result = audit_store.query_recent_events(100)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['event_type'], 'SYSTEM_STARTUP', "Should return correct event type")
    
    def test_query_recent_events_permission_denied(self, audit_store):
        """Test query recent events with permission denied error."""
        query_mock = Mock()
        query_mock.order_by.return_value.limit.return_value.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.order_by.return_value = query_mock
        
        result = audit_store.query_recent_events(100)
        
        assert_equals(result, [], "Should return empty list on permission denied")
    
    def test_query_events_by_tenant_success(self, audit_store):
        """Test successful query events by tenant."""
        audit_data = {
            'event_type': 'LOGIN_SUCCESS',
            'tenant_id': 'test_tenant',
            'username': 'testuser',
            'timestamp_ms': int(time.time() * 1000),
            'details': {}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_tenant('test_tenant', 100)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['tenant_id'], 'test_tenant', "Should return correct tenant ID")
    
    def test_query_events_by_tenant_permission_denied(self, audit_store):
        """Test query events by tenant with permission denied error."""
        query_mock = Mock()
        query_mock.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_tenant('test_tenant', 100)
        
        assert_equals(result, [], "Should return empty list on permission denied")
    
    def test_query_events_window_success(self, audit_store):
        """Test successful query events within time window."""
        start_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        end_time = int(time.time() * 1000)
        
        audit_data = {
            'event_type': 'LOGIN_SUCCESS',
            'timestamp_ms': int(time.time() * 1000) - 1800000,  # 30 minutes ago
            'username': 'testuser',
            'details': {}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_window(start_time, end_time, limit=1000)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['event_type'], 'LOGIN_SUCCESS', "Should return correct event type")
    
    def test_query_events_window_with_event_type_filter(self, audit_store):
        """Test query events window with event type filter."""
        start_time = int(time.time() * 1000) - 3600000  # 1 hour ago
        end_time = int(time.time() * 1000)
        
        audit_data = {
            'event_type': 'LOGIN_FAILURE',
            'timestamp_ms': int(time.time() * 1000) - 1800000,  # 30 minutes ago
            'username': 'testuser',
            'details': {}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_window(start_time, end_time, event_type='LOGIN_FAILURE', limit=1000)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['event_type'], 'LOGIN_FAILURE', "Should return correct event type")
    
    def test_query_events_window_permission_denied(self, audit_store):
        """Test query events window with permission denied error."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        
        query_mock = Mock()
        query_mock.where.return_value.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_window(start_time, end_time, limit=1000)
        
        assert_equals(result, [], "Should return empty list on permission denied")
    
    def test_query_events_window_exception(self, audit_store):
        """Test query events window with general exception."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        
        query_mock = Mock()
        query_mock.where.return_value.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = Exception("Test error")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_window(start_time, end_time, limit=1000)
        
        assert_equals(result, [], "Should return empty list on exception")
    
    def test_query_events_window_no_event_type_filter(self, audit_store):
        """Test query events window without event type filter."""
        start_time = int(time.time() * 1000) - 3600000
        end_time = int(time.time() * 1000)
        
        audit_data = {
            'event_type': 'LOGIN_SUCCESS',
            'timestamp_ms': int(time.time() * 1000) - 1800000,
            'username': 'testuser',
            'details': {}
        }
        
        mock_doc = Mock()
        mock_doc.id = 'doc1'
        mock_doc.to_dict.return_value = audit_data
        
        # When no event_type is provided, the query should not call .where() for event_type
        query_mock = Mock()
        query_mock.where.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.stream.return_value = [mock_doc]
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_window(start_time, end_time, event_type=None, limit=1000)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['event_type'], 'LOGIN_SUCCESS', "Should return correct event type")
