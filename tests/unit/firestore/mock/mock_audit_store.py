"""Mock Firestore audit data access layer with repository pattern."""

import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from unittest.mock import Mock

from .mock_base import MockTenantTimestampedRepository, MockQueryOptions, MockPaginatedResult, MockOperationResult
from .mock_models import MockAuditEvent, create_mock_audit_event

logger = logging.getLogger(__name__)


class MockAuditRepository(MockTenantTimestampedRepository):
    """Mock audit repository with multi-tenant support and timestamping."""
    
    def __init__(self, client: Mock):
        """Initialize with mock Firestore client."""
        super().__init__(client, 'audit')
        self.required_fields = ['timestamp_ms', 'utc_timestamp', 'event_type']
    
    def create(self, entity: MockAuditEvent) -> MockOperationResult[str]:
        """Create a new audit event."""
        try:
            # Validate entity
            self._validate_required_fields(entity.to_dict(), self.required_fields)
            
            # Ensure tenant isolation if tenant_id is provided
            data = entity.to_dict()
            if entity.tenant_id:
                data = self._enforce_tenant_isolation(entity.tenant_id, data)
            
            # Add timestamps
            data = self._add_timestamps(data)
            
            # Add document with auto-generated ID
            doc_ref = self.collection.add(data)
            doc_id = doc_ref[1].id
            
            self.logger.debug(f"Created audit event {doc_id} of type {entity.event_type}")
            return MockOperationResult(success=True, data=doc_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("create audit event", e)
    
    def get_by_id(self, entity_id: str) -> MockOperationResult[MockAuditEvent]:
        """Get audit event by ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return MockOperationResult(success=False, error="Audit event not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            event = create_mock_audit_event(data)
            event.id = doc.id
            
            return MockOperationResult(success=True, data=event)
            
        except Exception as e:
            self._handle_mock_firestore_error("get audit event by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> MockOperationResult[MockAuditEvent]:
        """Update audit event (generally not recommended for audit logs)."""
        try:
            # Add update timestamp
            updates = self._add_timestamps(updates, include_updated=True)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated event
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("update audit event", e)
    
    def delete(self, entity_id: str) -> MockOperationResult[bool]:
        """Delete audit event (generally not recommended for audit logs)."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.debug(f"Deleted audit event {entity_id}")
            return MockOperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_mock_firestore_error("delete audit event", e)
    
    # Audit-specific query methods
    def query_by_event_type(self, tenant_id: str, event_type: str,
                           options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query audit events by event type."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'event_type': event_type
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by event type", e)
    
    def query_by_user(self, tenant_id: str, user_id: str,
                     options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query audit events by user ID."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'user_id': user_id
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by user", e)
    
    def query_by_timestamp_range(self, tenant_id: str, start_time_ms: int, end_time_ms: int,
                                options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query audit events within a timestamp range."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'timestamp_ms': ('>=', start_time_ms),
                'timestamp_ms': ('<=', end_time_ms)
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'ASCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by timestamp range", e)
    
    def query_by_ip_address(self, tenant_id: str, ip_address: str,
                           options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query audit events by IP address."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'ip_address': ip_address
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by ip address", e)
    
    def query_login_events(self, tenant_id: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query login-related audit events."""
        try:
            options = options or MockQueryOptions()
            login_event_types = ['LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'SESSION_EXPIRED']
            
            # Note: This is a simplified implementation
            # In a real implementation, you might use array-contains or multiple queries
            options.filters = {
                'tenant_id': tenant_id,
                'event_type': 'LOGIN_SUCCESS'  # Simplified for mock
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query login events", e)
    
    def query_failed_attempts(self, tenant_id: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query failed authentication attempts."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'event_type': 'LOGIN_FAILED'
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query failed attempts", e)
    
    def query_recent_events(self, tenant_id: str, hours: int = 24,
                           options: MockQueryOptions = None) -> MockPaginatedResult[MockAuditEvent]:
        """Query recent audit events."""
        try:
            options = options or MockQueryOptions()
            current_time = int(time.time() * 1000)
            start_time = current_time - (hours * 3600 * 1000)  # Convert hours to milliseconds
            
            options.filters = {
                'tenant_id': tenant_id,
                'timestamp_ms': ('>=', start_time)
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query recent events", e)
    
    def get_event_statistics(self, tenant_id: str, start_time_ms: int, end_time_ms: int) -> MockOperationResult[Dict[str, Any]]:
        """Get audit event statistics for a time period."""
        try:
            options = MockQueryOptions(limit=10000)  # Get all events in range
            result = self.query_by_timestamp_range(tenant_id, start_time_ms, end_time_ms, options)
            
            if not result.items:
                return MockOperationResult(success=False, error="No events found", error_code="NOT_FOUND")
            
            events = result.items
            
            # Calculate statistics
            event_types = {}
            user_activity = {}
            ip_addresses = {}
            
            for event in events:
                # Count event types
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
                
                # Count user activity
                if event.user_id:
                    user_activity[event.user_id] = user_activity.get(event.user_id, 0) + 1
                
                # Count IP addresses
                if event.ip_address:
                    ip_addresses[event.ip_address] = ip_addresses.get(event.ip_address, 0) + 1
            
            stats = {
                'total_events': len(events),
                'event_types': event_types,
                'user_activity': user_activity,
                'ip_addresses': ip_addresses,
                'start_time_ms': start_time_ms,
                'end_time_ms': end_time_ms,
                'most_active_user': max(user_activity.items(), key=lambda x: x[1])[0] if user_activity else None,
                'most_common_event': max(event_types.items(), key=lambda x: x[1])[0] if event_types else None
            }
            
            return MockOperationResult(success=True, data=stats)
            
        except Exception as e:
            self._handle_mock_firestore_error("get event statistics", e)
    
    def cleanup_old_events(self, tenant_id: str, retention_days: int = 90) -> MockOperationResult[int]:
        """Clean up old audit events (mock implementation)."""
        try:
            current_time = int(time.time() * 1000)
            cutoff_time = current_time - (retention_days * 24 * 3600 * 1000)
            
            options = MockQueryOptions(limit=10000)
            options.filters = {
                'tenant_id': tenant_id,
                'timestamp_ms': ('<', cutoff_time)
            }
            
            result = self._execute_query(options)
            
            deleted_count = 0
            for event in result.items:
                delete_result = self.delete(event.id)
                if delete_result.success:
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old audit events for tenant {tenant_id}")
            return MockOperationResult(success=True, data=deleted_count)
            
        except Exception as e:
            self._handle_mock_firestore_error("cleanup old events", e)
    
    # Audit-specific logging methods (matching original AuditLogStore interface)
    def log_event(self, event_type: str, user_id: Optional[str] = None, username: Optional[str] = None,
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None) -> bool:
        """Log an audit event."""
        try:
            current_time = int(time.time() * 1000)
            utc_timestamp = datetime.fromtimestamp(current_time / 1000, tz=timezone.utc).isoformat()
            
            audit_doc = {
                'timestamp_ms': current_time,
                'utc_timestamp': utc_timestamp,
                'event_type': event_type,
                'user_id': user_id,
                'username': username,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'details': details or {},
                'tenant_id': tenant_id
            }
            
            # Add document with auto-generated ID
            doc_ref = self.collection.add(audit_doc)
            
            self.logger.debug(f"Logged audit event: {event_type} for user {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
            return False
    
    def log_auth_success(self, username: str, ip_address: str, session_id: str,
                        tenant_id: Optional[str] = None) -> bool:
        """Log successful authentication."""
        return self.log_event(
            event_type='LOGIN_SUCCESS',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )
    
    def log_auth_failure(self, username: str, ip_address: str, failure_reason: str,
                        tenant_id: Optional[str] = None) -> bool:
        """Log failed authentication."""
        return self.log_event(
            event_type='LOGIN_FAILURE',
            username=username,
            ip_address=ip_address,
            details={'failure_reason': failure_reason},
            tenant_id=tenant_id
        )
    
    def log_session_creation(self, username: str, session_id: str, ip_address: str,
                           tenant_id: Optional[str] = None) -> bool:
        """Log session creation."""
        return self.log_event(
            event_type='SESSION_CREATED',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )
    
    def log_session_destruction(self, session_id: str, username: Optional[str] = None,
                              ip_address: Optional[str] = None, tenant_id: Optional[str] = None) -> bool:
        """Log session destruction."""
        return self.log_event(
            event_type='SESSION_DESTROYED',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )
    
    def log_permission_denied(self, username: Optional[str] = None, user_id: Optional[str] = None,
                            ip_address: Optional[str] = None, resource: Optional[str] = None,
                            tenant_id: Optional[str] = None, reason: str = "INSUFFICIENT_PERMISSIONS") -> bool:
        """Log permission denied event."""
        return self.log_event(
            event_type='PERMISSION_DENIED',
            username=username,
            user_id=user_id,
            ip_address=ip_address,
            details={'resource': resource, 'reason': reason},
            tenant_id=tenant_id
        )
    
    def log_tenant_violation(self, username: Optional[str] = None, user_id: Optional[str] = None,
                           ip_address: Optional[str] = None, attempted_tenant: Optional[str] = None,
                           allowed_tenant: Optional[str] = None) -> bool:
        """Log multi-tenant access violation."""
        return self.log_event(
            event_type='TENANT_VIOLATION',
            username=username,
            user_id=user_id,
            ip_address=ip_address,
            details={
                'attempted_tenant': attempted_tenant,
                'allowed_tenant': allowed_tenant
            },
            tenant_id=attempted_tenant
        )
    
    # Query methods (matching original AuditLogStore interface)
    def query_events_by_user(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by user ID."""
        try:
            query = (self.collection
                    .where('user_id', '==', user_id)
                    .order_by('timestamp_ms', direction='DESCENDING')
                    .limit(limit))
            
            docs = list(query.stream())
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            self.logger.debug(f"Retrieved {len(results)} audit events for user {user_id}")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query audit events: {e}")
            return []
    
    def query_events_by_type(self, event_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by event type."""
        try:
            query = (self.collection
                    .where('event_type', '==', event_type)
                    .order_by('timestamp_ms', direction='DESCENDING')
                    .limit(limit))
            
            docs = list(query.stream())
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            self.logger.debug(f"Retrieved {len(results)} audit events of type {event_type}")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query audit events by type: {e}")
            return []
    
    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Query recent audit events."""
        try:
            query = (self.collection
                    .order_by('timestamp_ms', direction='DESCENDING')
                    .limit(limit))
            
            docs = list(query.stream())
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            self.logger.debug(f"Retrieved {len(results)} recent audit events")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query recent audit events: {e}")
            return []
    
    def query_events_by_tenant(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query audit events by tenant."""
        try:
            query = (self.collection
                    .where('tenant_id', '==', tenant_id)
                    .order_by('timestamp_ms', direction='DESCENDING')
                    .limit(limit))
            
            docs = list(query.stream())
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            self.logger.debug(f"Retrieved {len(results)} audit events for tenant {tenant_id}")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query audit events by tenant: {e}")
            return []
    
    def query_events_window(self, start_time_ms: int, end_time_ms: int, 
                           event_type: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Query audit events within a time window."""
        try:
            query = (self.collection
                    .where('timestamp_ms', '>=', start_time_ms)
                    .where('timestamp_ms', '<=', end_time_ms)
                    .order_by('timestamp_ms', direction='DESCENDING')
                    .limit(limit))
            
            # Add event type filter if specified
            if event_type:
                query = query.where('event_type', '==', event_type)
            
            docs = list(query.stream())
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            self.logger.debug(f"Retrieved {len(results)} audit events in time window")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query audit events in window: {e}")
            return []

    def _execute_query(self, options: MockQueryOptions) -> MockPaginatedResult[MockAuditEvent]:
        """Execute a query with the given options."""
        query = self.collection
        
        # Apply query options
        query = self._apply_query_options(query, options)
        
        # Execute query
        docs = list(query.stream())
        
        # Convert to audit events
        events = []
        for doc in docs:
            data = doc.to_dict()
            event = create_mock_audit_event(data)
            event.id = doc.id
            events.append(event)
        
        # Check if there are more results
        has_more = len(docs) == options.limit
        next_offset = docs[-1].id if has_more and docs else None
        
        return MockPaginatedResult(
            items=events,
            has_more=has_more,
            next_offset=next_offset
        )


# Backward compatibility alias
MockAuditStore = MockAuditRepository
