"""Firestore sessions data access layer."""

import time
import logging
import secrets
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

logger = logging.getLogger(__name__)


class SessionsStore:
    """Firestore-based sessions data store."""
    
    def __init__(self, client: firestore.Client):
        """Initialize with Firestore client."""
        self.client = client
        self.collection = client.collection('sessions')
        
    def create_session(self, user_id: str, username: str, role: str, 
                      expires_in_seconds: int = 1800, request_info: Optional[Dict] = None) -> Optional[str]:
        """
        Create a new user session.
        
        Args:
            user_id: User identifier
            username: Username
            role: User role
            expires_in_seconds: Session expiration time in seconds
            request_info: Request information (IP, user agent, etc.)
            
        Returns:
            Session ID if successful, None otherwise
        """
        try:
            session_id = f"sess_{secrets.token_urlsafe(32)}"
            current_time = int(time.time() * 1000)
            expires_at = current_time + (expires_in_seconds * 1000)
            
            # Extract request info
            ip_address = request_info.get('ip_address', 'unknown') if request_info else 'unknown'
            user_agent = request_info.get('user_agent', 'unknown') if request_info else 'unknown'
            
            # Create fingerprint for session binding
            fingerprint = self._create_fingerprint(ip_address, user_agent)
            
            session_doc = {
                'session_id': session_id,
                'user_id': user_id,
                'username': username,
                'role': role,
                'created_at': current_time,
                'expires_at': expires_at,
                'last_access': current_time,
                'fingerprint': fingerprint,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'tenant_id': request_info.get('tenant_id') if request_info else None
            }
            
            # Store session document
            doc_ref = self.collection.document(session_id)
            doc_ref.set(session_doc)
            
            logger.info(f"Created session {session_id} for user {username}")
            return session_id
            
        except PermissionDenied as e:
            logger.error(f"Permission denied creating session: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session by session ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session document or None if not found/expired
        """
        try:
            doc_ref = self.collection.document(session_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return None
                
            session_data = doc.to_dict()
            
            # Check if session is expired
            current_time = int(time.time() * 1000)
            if session_data.get('expires_at', 0) <= current_time:
                logger.debug(f"Session {session_id} has expired")
                return None
                
            session_data['id'] = doc.id
            return session_data
            
        except PermissionDenied as e:
            logger.error(f"Permission denied getting session: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    def update_session_access(self, session_id: str) -> bool:
        """
        Update session last access time.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            current_time = int(time.time() * 1000)
            doc_ref = self.collection.document(session_id)
            doc_ref.update({'last_access': current_time})
            
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied updating session access: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to update session access: {e}")
            return False
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session by deleting it.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            doc_ref = self.collection.document(session_id)
            doc_ref.delete()
            
            logger.info(f"Invalidated session {session_id}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied invalidating session: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to invalidate session: {e}")
            return False
    
    def invalidate_user_sessions(self, user_id: str, exclude_session_id: Optional[str] = None) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User identifier
            exclude_session_id: Session ID to exclude from invalidation
            
        Returns:
            Number of sessions invalidated
        """
        try:
            query = self.collection.where('user_id', '==', user_id)
            docs = query.stream()
            
            invalidated_count = 0
            for doc in docs:
                session_id = doc.id
                
                # Skip excluded session
                if exclude_session_id and session_id == exclude_session_id:
                    continue
                    
                doc.reference.delete()
                invalidated_count += 1
                
            logger.info(f"Invalidated {invalidated_count} sessions for user {user_id}")
            return invalidated_count
            
        except PermissionDenied as e:
            logger.error(f"Permission denied invalidating user sessions: {e}")
            return 0
        except Exception as e:
            logger.error(f"Failed to invalidate user sessions: {e}")
            return 0
    
    def rotate_session(self, old_session_id: str, user_id: str, username: str, role: str,
                      expires_in_seconds: int = 1800, request_info: Optional[Dict] = None) -> Optional[str]:
        """
        Rotate session by creating new one and invalidating old one.
        
        Args:
            old_session_id: Current session ID to rotate
            user_id: User identifier
            username: Username
            role: User role
            expires_in_seconds: New session expiration time
            request_info: Request information
            
        Returns:
            New session ID if successful, None otherwise
        """
        try:
            # Create new session
            new_session_id = self.create_session(
                user_id, username, role, expires_in_seconds, request_info
            )
            
            if not new_session_id:
                return None
                
            # Invalidate old session
            self.invalidate_session(old_session_id)
            
            logger.info(f"Rotated session {old_session_id} to {new_session_id}")
            return new_session_id
            
        except Exception as e:
            logger.error(f"Failed to rotate session: {e}")
            return None
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            current_time = int(time.time() * 1000)
            query = self.collection.where('expires_at', '<=', current_time)
            
            docs = query.stream()
            cleaned_count = 0
            
            for doc in docs:
                doc.reference.delete()
                cleaned_count += 1
                
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
                
            return cleaned_count
            
        except PermissionDenied as e:
            logger.error(f"Permission denied cleaning up sessions: {e}")
            return 0
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    def get_active_sessions_count(self, user_id: str) -> int:
        """
        Get count of active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of active sessions
        """
        try:
            current_time = int(time.time() * 1000)
            query = (self.collection
                    .where('user_id', '==', user_id)
                    .where('expires_at', '>', current_time))
            
            docs = query.stream()
            count = sum(1 for _ in docs)
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to get active sessions count: {e}")
            return 0
    
    def _create_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """
        Create a session fingerprint from request info.
        
        Args:
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Fingerprint string
        """
        import hashlib
        
        # Create a hash of IP and user agent for fingerprinting
        fingerprint_data = f"{ip_address}:{user_agent}"
        fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        
        return f"fp_{fingerprint_hash}"
