"""Firestore audit log data access layer."""

import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

logger = logging.getLogger(__name__)


class AuditLogStore:
    """Firestore-based audit log data store."""
    
    def __init__(self, client: firestore.Client):
        """Initialize with Firestore client."""
        self.client = client
        self.collection = client.collection('audit_log')
        
    def log_event(self, event_type: str, user_id: Optional[str] = None, username: Optional[str] = None,
                 ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None) -> bool:
        """
        Log an audit event.
        
        Args:
            event_type: Type of event (e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'PERMISSION_DENIED')
            user_id: User identifier (if applicable)
            username: Username (if applicable)
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional event details
            tenant_id: Tenant identifier (if applicable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            current_time = int(time.time() * 1000)
            utc_timestamp = datetime.utcfromtimestamp(current_time / 1000).isoformat() + 'Z'
            
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
            
            logger.debug(f"Logged audit event: {event_type} for user {username}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied logging audit event: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False
    
    def log_auth_success(self, username: str, ip_address: str, session_id: str,
                        tenant_id: Optional[str] = None) -> bool:
        """
        Log successful authentication.
        
        Args:
            username: Username
            ip_address: Client IP address
            session_id: Session identifier
            tenant_id: Tenant identifier
            
        Returns:
            True if successful, False otherwise
        """
        return self.log_event(
            event_type='LOGIN_SUCCESS',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )
    
    def log_auth_failure(self, username: str, ip_address: str, failure_reason: str,
                        tenant_id: Optional[str] = None) -> bool:
        """
        Log failed authentication.
        
        Args:
            username: Username
            ip_address: Client IP address
            failure_reason: Reason for failure
            tenant_id: Tenant identifier
            
        Returns:
            True if successful, False otherwise
        """
        return self.log_event(
            event_type='LOGIN_FAILURE',
            username=username,
            ip_address=ip_address,
            details={'failure_reason': failure_reason},
            tenant_id=tenant_id
        )
    
    def log_session_creation(self, username: str, session_id: str, ip_address: str,
                           tenant_id: Optional[str] = None) -> bool:
        """
        Log session creation.
        
        Args:
            username: Username
            session_id: Session identifier
            ip_address: Client IP address
            tenant_id: Tenant identifier
            
        Returns:
            True if successful, False otherwise
        """
        return self.log_event(
            event_type='SESSION_CREATED',
            username=username,
            ip_address=ip_address,
            details={'session_id': session_id},
            tenant_id=tenant_id
        )
    
    def log_session_destruction(self, session_id: str, username: Optional[str] = None,
                              ip_address: Optional[str] = None, tenant_id: Optional[str] = None) -> bool:
        """
        Log session destruction.
        
        Args:
            session_id: Session identifier
            username: Username (if known)
            ip_address: Client IP address
            tenant_id: Tenant identifier
            
        Returns:
            True if successful, False otherwise
        """
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
        """
        Log permission denied event.
        
        Args:
            username: Username (if known)
            user_id: User identifier (if known)
            ip_address: Client IP address
            resource: Resource that was accessed
            tenant_id: Tenant identifier
            reason: Reason for denial
            
        Returns:
            True if successful, False otherwise
        """
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
        """
        Log multi-tenant access violation.
        
        Args:
            username: Username (if known)
            user_id: User identifier (if known)
            ip_address: Client IP address
            attempted_tenant: Tenant that was attempted to access
            allowed_tenant: Tenant that user is allowed to access
            
        Returns:
            True if successful, False otherwise
        """
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
    
    def query_events_by_user(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit events by user ID.
        
        Args:
            user_id: User identifier
            limit: Maximum number of events to return
            
        Returns:
            List of audit events
        """
        try:
            query = (self.collection
                    .where('user_id', '==', user_id)
                    .order_by('timestamp_ms', direction=firestore.Query.DESCENDING)
                    .limit(limit))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            logger.debug(f"Retrieved {len(results)} audit events for user {user_id}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied querying audit events: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")
            return []
    
    def query_events_by_type(self, event_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit events by event type.
        
        Args:
            event_type: Event type to query
            limit: Maximum number of events to return
            
        Returns:
            List of audit events
        """
        try:
            query = (self.collection
                    .where('event_type', '==', event_type)
                    .order_by('timestamp_ms', direction=firestore.Query.DESCENDING)
                    .limit(limit))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            logger.debug(f"Retrieved {len(results)} audit events of type {event_type}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied querying audit events by type: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query audit events by type: {e}")
            return []
    
    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query recent audit events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of audit events
        """
        try:
            query = (self.collection
                    .order_by('timestamp_ms', direction=firestore.Query.DESCENDING)
                    .limit(limit))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            logger.debug(f"Retrieved {len(results)} recent audit events")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied querying recent audit events: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query recent audit events: {e}")
            return []
    
    def query_events_by_tenant(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit events by tenant.
        
        Args:
            tenant_id: Tenant identifier
            limit: Maximum number of events to return
            
        Returns:
            List of audit events
        """
        try:
            query = (self.collection
                    .where('tenant_id', '==', tenant_id)
                    .order_by('timestamp_ms', direction=firestore.Query.DESCENDING)
                    .limit(limit))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            logger.debug(f"Retrieved {len(results)} audit events for tenant {tenant_id}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied querying audit events by tenant: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query audit events by tenant: {e}")
            return []
    
    def query_events_window(self, start_time_ms: int, end_time_ms: int, 
                          event_type: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Query audit events within a time window.
        
        Args:
            start_time_ms: Start timestamp in milliseconds
            end_time_ms: End timestamp in milliseconds
            event_type: Optional event type filter
            limit: Maximum number of events to return
            
        Returns:
            List of audit events
        """
        try:
            query = (self.collection
                    .where('timestamp_ms', '>=', start_time_ms)
                    .where('timestamp_ms', '<=', end_time_ms)
                    .order_by('timestamp_ms', direction=firestore.Query.DESCENDING)
                    .limit(limit))
            
            # Add event type filter if specified
            if event_type:
                query = query.where('event_type', '==', event_type)
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                data = doc.to_dict()
                data['id'] = doc.id
                results.append(data)
                
            logger.debug(f"Retrieved {len(results)} audit events in time window")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied querying audit events in window: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query audit events in window: {e}")
            return []
