"""Tests for AuditLogStore with contract-based validation."""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

# Legacy mock imports (to be phased out)
from adapters.db.firestore.audit_store import AuditLogStore
from google.api_core.exceptions import PermissionDenied

# Contract testing imports
from tests.contracts.base import AuditStoreProtocol
from tests.contracts.firestore import ContractValidator, ContractEnforcer
from tests.contracts.mocks import MockFirestoreClient
from tests.utils.business_rules import BusinessRules
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_not_none, assert_is_none, assert_is_instance, assert_raises

# E2E testing imports
import os
from adapters.db.firestore.client import FirestoreClientFactory


@pytest.mark.auth
@pytest.mark.unit
@pytest.mark.contract
class TestAuditLogStore:
    """Test cases for AuditLogStore with contract validation."""

    @pytest.fixture
    def contract_validator(self):
        """Provide contract validator for validation."""
        return ContractValidator()

    @pytest.fixture
    def business_rules(self):
        """Provide business rules for validation."""
        return BusinessRules()

    @pytest.fixture
    def contract_enforcer(self):
        """Provide contract enforcer for strict validation."""
        return ContractEnforcer()

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

    @pytest.fixture
    def valid_audit_data(self) -> Dict[str, Any]:
        """Provide valid audit event data for testing."""
        return {
            'event_type': 'LOGIN_SUCCESS',
            'user_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
            'username': 'testuser',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)',
            'details': {'session_id': 'f47ac10b-58cc-4372-a567-0e02b2c3d479'},
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6'
        }

    @pytest.fixture
    def firestore_emulator_client(self):
        """Create a real Firestore client connected to emulator for E2E testing."""
        # Use emulator if available, otherwise skip
        emulator_host = os.environ.get('FIRESTORE_EMULATOR_HOST')
        if not emulator_host:
            pytest.skip("Firestore emulator not available for E2E testing")

        try:
            client = FirestoreClientFactory.create_client(
                emulator_host=emulator_host,
                project_id='test-project'
            )
            yield client
        except Exception as e:
            pytest.skip(f"Failed to create Firestore emulator client: {e}")

    @pytest.fixture
    def e2e_audit_store(self, firestore_emulator_client):
        """Create AuditLogStore with real Firestore client for E2E testing."""
        return AuditLogStore(firestore_emulator_client)

    @pytest.fixture
    def isolated_test_tenant(self):
        """Generate an isolated tenant ID for E2E tests to avoid conflicts."""
        import uuid
        return f"e2e-test-tenant-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def cleanup_e2e_data(self, firestore_emulator_client, isolated_test_tenant):
        """Clean up E2E test data after tests."""
        yield

        # Clean up test data
        try:
            # Delete all audit events for the test tenant
            audit_collection = firestore_emulator_client.collection('audit_log')
            docs = audit_collection.where('tenant_id', '==', isolated_test_tenant).stream()

            for doc in docs:
                doc.reference.delete()

        except Exception as e:
            # Log cleanup errors but don't fail the test
            print(f"Warning: Failed to clean up E2E test data: {e}")

    @pytest.fixture
    def e2e_contract_validator(self):
        """Contract validator configured for E2E testing."""
        validator = ContractValidator()
        # In E2E mode, we might want different validation rules
        return validator
    
    def test_init(self, mock_client):
        """Test store initialization."""
        store = AuditLogStore(mock_client)
        assert store.client == mock_client
        assert store.collection == mock_client.collection.return_value
    
    def test_log_event_success(self, audit_store, contract_validator, contract_enforcer, business_rules, valid_audit_data):
        """Test successful event logging with contract validation."""
        # Pre-validate data against business rules
        auth_result = business_rules.auth_check(
            user_id=valid_audit_data['user_id'],
            tenant_id=valid_audit_data['tenant_id']
        )
        assert_true(auth_result['valid'], f"Auth validation failed: {auth_result['violations']}")

        # Validate audit data structure against contract
        audit_data_for_contract = valid_audit_data.copy()
        audit_data_for_contract['timestamp_ms'] = int(time.time() * 1000)
        audit_data_for_contract['utc_timestamp'] = datetime.utcnow().isoformat() + '+00:00'

        validation_result = contract_validator.validate_create_operation(
            audit_data_for_contract,
            'audit_event',
            tenant_id=valid_audit_data['tenant_id'],
            user_id=valid_audit_data['user_id']
        )
        assert_true(validation_result.valid, f"Contract validation failed: {validation_result.violations}")

        result = audit_store.log_event(**valid_audit_data)

        assert_true(result, "Log event should succeed")
        audit_store.collection.add.assert_called_once()

        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_SUCCESS', "Should set event type")
        assert_equals(call_args['user_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set user ID")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
        assert_is_instance(call_args['timestamp_ms'], int, "Should set timestamp_ms")
        assert_true(
            call_args['utc_timestamp'].endswith('+00:00') or call_args['utc_timestamp'].endswith('Z'),
            "Should set UTC timestamp"
        )

        # Post-validate the stored data against contract
        contract_enforcer.enforce_create_contract(
            call_args,
            required_fields=['event_type', 'timestamp_ms', 'utc_timestamp'],
            tenant_id=valid_audit_data['tenant_id']
        )
    
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
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
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
            session_id='f47ac10b-58cc-4372-a567-0e02b2c3d479',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        
        assert_true(result, "Log auth success should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_SUCCESS', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'f47ac10b-58cc-4372-a567-0e02b2c3d479', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
    
    def test_log_auth_failure(self, audit_store):
        """Test failed authentication logging."""
        result = audit_store.log_auth_failure(
            username='testuser',
            ip_address='192.168.1.100',
            failure_reason='Invalid password',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        
        assert_true(result, "Log auth failure should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'LOGIN_FAILURE', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['failure_reason'], 'Invalid password', "Should set failure reason in details")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
    
    def test_log_session_creation(self, audit_store):
        """Test session creation logging."""
        result = audit_store.log_session_creation(
            username='testuser',
            session_id='f47ac10b-58cc-4372-a567-0e02b2c3d479',
            ip_address='192.168.1.100',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        
        assert_true(result, "Log session creation should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_CREATED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'f47ac10b-58cc-4372-a567-0e02b2c3d479', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
    
    def test_log_session_destruction(self, audit_store):
        """Test session destruction logging."""
        result = audit_store.log_session_destruction(
            session_id='f47ac10b-58cc-4372-a567-0e02b2c3d479',
            username='testuser',
            ip_address='192.168.1.100',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6'
        )
        
        assert_true(result, "Log session destruction should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_DESTROYED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['session_id'], 'f47ac10b-58cc-4372-a567-0e02b2c3d479', "Should set session ID in details")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
    
    def test_log_session_destruction_minimal_data(self, audit_store):
        """Test session destruction logging with minimal data."""
        result = audit_store.log_session_destruction(
            session_id='f47ac10b-58cc-4372-a567-0e02b2c3d479'
        )
        
        assert_true(result, "Log session destruction should succeed with minimal data")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'SESSION_DESTROYED', "Should set correct event type")
        assert_equals(call_args['details']['session_id'], 'f47ac10b-58cc-4372-a567-0e02b2c3d479', "Should set session ID in details")
        assert_is_none(call_args.get('username'), "Should not set username when not provided")
        assert_is_none(call_args.get('ip_address'), "Should not set IP address when not provided")

    def test_log_auth_success_failure(self, audit_store):
        """Wrapper should propagate failure from log_event."""
        audit_store.log_event = Mock(return_value=False)
       
        result = audit_store.log_auth_success(
            username='testuser', ip_address='192.168.1.100', session_id='sess'
        )
        assert_false(result, "Wrapper should return False when log_event fails")

    def test_log_auth_failure_failure(self, audit_store):
        audit_store.log_event = Mock(return_value=False)
        result = audit_store.log_auth_failure(
            username='testuser', ip_address='192.168.1.100', failure_reason='bad'
        )
        assert_false(result)

    def test_log_session_creation_failure(self, audit_store):
        audit_store.log_event = Mock(return_value=False)
        result = audit_store.log_session_creation(
            username='testuser', session_id='sess', ip_address='192.168.1.100'
        )
        assert_false(result)

    def test_log_session_destruction_failure(self, audit_store):
        audit_store.log_event = Mock(return_value=False)
        result = audit_store.log_session_destruction(
            session_id='sess', username='testuser', ip_address='192.168.1.100'
        )
        assert_false(result)

    def test_log_permission_denied_wrapper_failure(self, audit_store):
        audit_store.log_event = Mock(return_value=False)
        result = audit_store.log_permission_denied(
            username='testuser', user_id='uid', ip_address='1.1.1.1', resource='/x'
        )
        assert_false(result)

    def test_log_tenant_violation_failure(self, audit_store):
        audit_store.log_event = Mock(return_value=False)
        result = audit_store.log_tenant_violation(
            username='testuser', user_id='uid', ip_address='1.1.1.1', attempted_tenant='t2', allowed_tenant='t1'
        )
        assert_false(result)
    
    def test_log_permission_denied(self, audit_store):
        """Test permission denied logging."""
        result = audit_store.log_permission_denied(
            username='testuser',
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            ip_address='192.168.1.100',
            resource='/api/sensitive-data',
            tenant_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            reason='INSUFFICIENT_PERMISSIONS'
        )
        
        assert_true(result, "Log permission denied should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'PERMISSION_DENIED', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['user_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set user ID")
        assert_equals(call_args['ip_address'], '192.168.1.100', "Should set IP address")
        assert_equals(call_args['details']['resource'], '/api/sensitive-data', "Should set resource in details")
        assert_equals(call_args['details']['reason'], 'INSUFFICIENT_PERMISSIONS', "Should set reason in details")
        assert_equals(call_args['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set tenant ID")
    
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
            user_id='3fa85f64-5717-4562-b3fc-2c963f66afa6',
            ip_address='192.168.1.100',
            attempted_tenant='tenant_b',
            allowed_tenant='tenant_a'
        )
        
        assert_true(result, "Log tenant violation should succeed")
        
        # Verify the logged data structure
        call_args = audit_store.collection.add.call_args[0][0]
        assert_equals(call_args['event_type'], 'TENANT_VIOLATION', "Should set correct event type")
        assert_equals(call_args['username'], 'testuser', "Should set username")
        assert_equals(call_args['user_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should set user ID")
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
            'tenant_id': '3fa85f64-5717-4562-b3fc-2c963f66afa6',
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
        
        result = audit_store.query_events_by_tenant('3fa85f64-5717-4562-b3fc-2c963f66afa6', 100)
        
        assert_equals(len(result), 1, "Should return 1 event")
        assert_equals(result[0]['id'], 'doc1', "Should set document ID")
        assert_equals(result[0]['tenant_id'], '3fa85f64-5717-4562-b3fc-2c963f66afa6', "Should return correct tenant ID")
    
    def test_query_events_by_tenant_permission_denied(self, audit_store):
        """Test query events by tenant with permission denied error."""
        query_mock = Mock()
        query_mock.where.return_value.order_by.return_value.limit.return_value.stream.side_effect = PermissionDenied("Permission denied")
        audit_store.collection.where.return_value = query_mock
        
        result = audit_store.query_events_by_tenant('3fa85f64-5717-4562-b3fc-2c963f66afa6', 100)
        
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

    # Contract-based validation tests
    def test_contract_validation_log_event(self, contract_validator, valid_audit_data):
        """Test contract validation for audit event logging."""
        # Test valid audit data
        audit_data = valid_audit_data.copy()
        audit_data.update({
            'timestamp_ms': int(time.time() * 1000),
            'utc_timestamp': datetime.utcnow().isoformat() + '+00:00'
        })

        # Should validate successfully
        validation_result = contract_validator.validate_create_operation(
            audit_data,
            'audit_event',
            tenant_id=valid_audit_data['tenant_id'],
            user_id=valid_audit_data['user_id']
        )
        assert_true(validation_result.valid, f"Valid audit data should pass validation: {validation_result.violations}")

    def test_contract_violation_invalid_event_type(self, contract_validator, valid_audit_data):
        """Test contract violation with invalid event type."""
        invalid_data = valid_audit_data.copy()
        invalid_data.update({
            'event_type': '',  # Empty event type should violate contract
            'timestamp_ms': int(time.time() * 1000),
            'utc_timestamp': datetime.utcnow().isoformat() + '+00:00'
        })

        validation_result = contract_validator.validate_create_operation(
            invalid_data,
            'audit_event',
            tenant_id=valid_audit_data['tenant_id'],
            user_id=valid_audit_data['user_id']
        )

        assert_false(validation_result.valid, "Invalid audit data should fail validation")
        assert_true(len(validation_result.violations) > 0, "Should have validation violations")
        assert_true(any("event_type" in violation.lower() or "required" in violation.lower()
                       for violation in validation_result.violations), "Should mention event_type or required fields")

    def test_business_rules_audit_event(self, business_rules, valid_audit_data):
        """Test business rules validation for audit events."""
        # Test valid audit event
        result = business_rules.audit_trail_check(
            operation='LOGIN_SUCCESS',
            user_id=valid_audit_data['user_id'],
            tenant_id=valid_audit_data['tenant_id']
        )

        assert_true(result['valid'], f"Audit trail validation failed: {result['violations']}")
        assert_true(result['audit_required'], "Audit should be required for login events")

        # Test audit event without tenant (should still be valid but flagged)
        result_no_tenant = business_rules.audit_trail_check(
            operation='SYSTEM_STARTUP',
            user_id=None,
            tenant_id=None
        )

        assert_true(result_no_tenant['valid'], "System startup should be valid without tenant")

    def test_query_contract_validation(self, audit_store, contract_validator, valid_audit_data):
        """Test contract validation for query operations."""
        from tests.contracts.base import QueryOptions

        tenant_id = valid_audit_data['tenant_id']
        user_id = valid_audit_data['user_id']

        # Validate query filters against contract
        query_options = QueryOptions(
            filters={
                'tenant_id': tenant_id,
                'user_id': user_id,
                'timestamp_ms': ('>=', int(time.time() * 1000) - 3600000)  # Last hour
            },
            limit=100
        )

        # Should validate successfully
        validation_result = contract_validator.validate_query_operation(
            query_options, 'audit_event', tenant_id=tenant_id, user_id=user_id
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
            invalid_options, 'audit_event', tenant_id=tenant_id, user_id=user_id
        )
        assert_false(invalid_result.valid, "Query without tenant isolation should fail validation")
        assert_true(any("tenant" in violation.lower() or "isolation" in violation.lower()
                       for violation in invalid_result.violations), "Should mention tenant or isolation")

    # E2E Tests using real Firestore emulator client
    @pytest.mark.e2e
    @pytest.mark.contract
    def test_e2e_log_event_success(self, e2e_audit_store, valid_audit_data, isolated_test_tenant,
                                   cleanup_e2e_data, e2e_contract_validator, business_rules):
        """E2E test for successful audit event logging with real Firestore client."""
        # Pre-validate data against business rules
        auth_result = business_rules.auth_check(
            user_id=valid_audit_data['user_id'],
            tenant_id=isolated_test_tenant
        )
        assert_true(auth_result['valid'], f"Auth validation failed: {auth_result['violations']}")

        # Prepare audit data for E2E test
        audit_data = valid_audit_data.copy()
        audit_data['tenant_id'] = isolated_test_tenant
        audit_data['timestamp_ms'] = int(time.time() * 1000)
        audit_data['utc_timestamp'] = datetime.utcnow().isoformat() + '+00:00'

        # Validate against contract before logging
        validation_result = e2e_contract_validator.validate_create_operation(
            audit_data,
            'audit_event',
            tenant_id=isolated_test_tenant,
            user_id=valid_audit_data['user_id']
        )
        assert_true(validation_result.valid, f"Contract validation failed: {validation_result.violations}")

        # Log event using real store
        result = e2e_audit_store.log_event(**audit_data)

        assert_true(result, "E2E log event should succeed")

    @pytest.mark.e2e
    @pytest.mark.contract
    def test_e2e_query_events_by_user(self, e2e_audit_store, valid_audit_data, isolated_test_tenant,
                                     cleanup_e2e_data, e2e_contract_validator):
        """E2E test for querying audit events by user with real Firestore client."""
        # First log some events
        audit_data1 = valid_audit_data.copy()
        audit_data1['tenant_id'] = isolated_test_tenant
        audit_data1['event_type'] = 'LOGIN_SUCCESS'

        audit_data2 = valid_audit_data.copy()
        audit_data2['tenant_id'] = isolated_test_tenant
        audit_data2['event_type'] = 'SESSION_CREATED'

        # Log events
        result1 = e2e_audit_store.log_event(**audit_data1)
        result2 = e2e_audit_store.log_event(**audit_data2)
        assert_true(result1 and result2, "Should successfully log events")

        # Query events by user
        events = e2e_audit_store.query_events_by_user(valid_audit_data['user_id'], limit=10)

        assert_true(len(events) >= 2, "Should return at least 2 events for user")
        assert_true(all(event['user_id'] == valid_audit_data['user_id'] for event in events),
                   "All events should belong to the queried user")

        # Validate contract compliance for retrieved data
        for event in events:
            validation_result = e2e_contract_validator.validate_read_operation(
                event, 'audit_event', tenant_id=isolated_test_tenant
            )
            assert_true(validation_result.valid, f"Retrieved event should pass contract validation: {validation_result.violations}")

    @pytest.mark.e2e
    @pytest.mark.contract
    def test_e2e_query_recent_events(self, e2e_audit_store, valid_audit_data, isolated_test_tenant,
                                    cleanup_e2e_data, e2e_contract_validator):
        """E2E test for querying recent audit events with real Firestore client."""
        # Log several events with different timestamps
        events_to_log = [
            ('LOGIN_SUCCESS', valid_audit_data['user_id']),
            ('SESSION_CREATED', valid_audit_data['user_id']),
            ('PERMISSION_DENIED', 'different-user-id'),
            ('SYSTEM_STARTUP', None)
        ]

        for event_type, user_id in events_to_log:
            audit_data = valid_audit_data.copy()
            audit_data['tenant_id'] = isolated_test_tenant
            audit_data['event_type'] = event_type
            audit_data['user_id'] = user_id
            if user_id is None:
                del audit_data['user_id']  # Remove None user_id for system events

            result = e2e_audit_store.log_event(**audit_data)
            assert_true(result, f"Should successfully log {event_type} event")

        # Query recent events
        recent_events = e2e_audit_store.query_recent_events(limit=10)

        assert_true(len(recent_events) >= 4, "Should return at least 4 recent events")
        # Events should be ordered by timestamp descending (most recent first)
        timestamps = [event['timestamp_ms'] for event in recent_events]
        assert_true(all(timestamps[i] >= timestamps[i+1] for i in range(len(timestamps)-1)),
                   "Events should be ordered by timestamp descending")

        # Validate contract compliance
        for event in recent_events:
            validation_result = e2e_contract_validator.validate_read_operation(
                event, 'audit_event', tenant_id=isolated_test_tenant
            )
            assert_true(validation_result.valid, f"Retrieved event should pass contract validation: {validation_result.violations}")

    @pytest.mark.e2e
    @pytest.mark.contract
    def test_e2e_tenant_isolation(self, e2e_audit_store, valid_audit_data, isolated_test_tenant,
                                 cleanup_e2e_data, e2e_contract_validator, business_rules):
        """E2E test for tenant isolation in audit events."""
        # Log event for our tenant
        audit_data = valid_audit_data.copy()
        audit_data['tenant_id'] = isolated_test_tenant

        result = e2e_audit_store.log_event(**audit_data)
        assert_true(result, "Should successfully log event for tenant")

        # Query events for our tenant
        tenant_events = e2e_audit_store.query_events_by_tenant(isolated_test_tenant, limit=10)

        assert_true(len(tenant_events) >= 1, "Should return at least 1 event for tenant")
        assert_true(all(event['tenant_id'] == isolated_test_tenant for event in tenant_events),
                   "All events should belong to the queried tenant")

        # Test tenant isolation validation
        for event in tenant_events:
            isolation_result = business_rules.tenant_isolation_check(
                tenant_id=isolated_test_tenant,
                resource_tenant_id=event['tenant_id']
            )
            assert_true(isolation_result['valid'], f"Tenant isolation check failed: {isolation_result['violations']}")

    @pytest.mark.e2e
    @pytest.mark.contract
    def test_e2e_audit_event_lifecycle(self, e2e_audit_store, valid_audit_data, isolated_test_tenant,
                                      cleanup_e2e_data, e2e_contract_validator, business_rules):
        """E2E test for complete audit event lifecycle with business rules validation."""
        # Test login success event
        login_data = valid_audit_data.copy()
        login_data['tenant_id'] = isolated_test_tenant
        login_data['event_type'] = 'LOGIN_SUCCESS'

        # Validate business rules for audit trail
        audit_result = business_rules.audit_trail_check(
            operation='LOGIN_SUCCESS',
            user_id=valid_audit_data['user_id'],
            tenant_id=isolated_test_tenant
        )
        assert_true(audit_result['valid'] and audit_result['audit_required'],
                   f"Audit trail validation failed: {audit_result['violations']}")

        result = e2e_audit_store.log_event(**login_data)
        assert_true(result, "Should successfully log login success")

        # Test session creation event
        session_data = valid_audit_data.copy()
        session_data['tenant_id'] = isolated_test_tenant
        session_data['event_type'] = 'SESSION_CREATED'
        session_data['details'] = {'session_id': 'test-session-id'}

        audit_result = business_rules.audit_trail_check(
            operation='SESSION_CREATED',
            user_id=valid_audit_data['user_id'],
            tenant_id=isolated_test_tenant
        )
        assert_true(audit_result['valid'] and audit_result['audit_required'],
                   f"Session audit validation failed: {audit_result['violations']}")

        result = e2e_audit_store.log_event(**session_data)
        assert_true(result, "Should successfully log session creation")

        # Query and validate both events exist
        user_events = e2e_audit_store.query_events_by_user(valid_audit_data['user_id'], limit=10)

        login_events = [e for e in user_events if e['event_type'] == 'LOGIN_SUCCESS']
        session_events = [e for e in user_events if e['event_type'] == 'SESSION_CREATED']

        assert_true(len(login_events) >= 1, "Should have at least 1 login event")
        assert_true(len(session_events) >= 1, "Should have at least 1 session event")

        # Validate data integrity for all events
        for event in user_events:
            integrity_result = business_rules.data_integrity_check(event)
            assert_true(integrity_result['valid'], f"Data integrity check failed: {integrity_result['violations']}")

            # Final contract validation
            validation_result = e2e_contract_validator.validate_read_operation(
                event, 'audit_event', tenant_id=isolated_test_tenant
            )
            assert_true(validation_result.valid, f"Final contract validation failed: {validation_result.violations}")
