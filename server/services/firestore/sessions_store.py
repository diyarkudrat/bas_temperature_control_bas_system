"""Firestore sessions data access layer with optional Redis read-through cache."""

import time
import json
import os
import logging
import secrets
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from google.cloud import firestore
from .cache_utils import (
    CacheClient,
    cap_ttl_seconds,
    normalize_key_part,
    ensure_text,
    json_dumps_compact,
    json_loads_safe,
)
from .lru_cache import LRUCache
from google.api_core.exceptions import NotFound, PermissionDenied

logger = logging.getLogger(__name__)


class SessionsStore:
    """Firestore-based sessions data store."""
    
    def __init__(self, client: firestore.Client, *, cache: Optional[CacheClient] = None):
        """Initialize with Firestore client and optional Redis-like cache.

        Cache client is expected to provide: get(key), setex(key, ttl_seconds, value), delete(key)
        """
        self.client = client
        self.collection = client.collection('sessions')
        self._cache = cache
        self._cache_prefix = os.getenv("SESSIONS_CACHE_PREFIX", "sess:")
        self._ttl_cap_s = int(os.getenv("SESSIONS_MAX_TTL_S", "1800"))
        # tiny in-process by-id cache
        self._lru = LRUCache(capacity=int(os.getenv("SESSIONS_LRU_CAPACITY", "128")), ttl_s=int(os.getenv("SESSIONS_LRU_TTL_S", "3")))

    def _cache_key(self, session_id: str) -> str:
        sid = self._normalize_session_id(session_id)
        return f"{self._cache_prefix}{sid}"

    def _normalize_session_id(self, session_id: Any) -> str:
        """Ensure idempotent, canonical session key material."""
        # Do not change case; session IDs are case-sensitive tokens
        # Trim incidental whitespace and coerce to str
        return normalize_key_part(session_id)
        
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

            # Prime cache with TTL bounded by expiry
            key = self._cache_key(session_id)
            # 1) LRU
            self._lru.set(key, {**session_doc, 'id': session_id})
            # 2) Redis
            if self._cache is not None:
                try:
                    # include id for consistency in cache
                    cached_doc = dict(session_doc)
                    cached_doc['id'] = session_id
                    ttl_s = cap_ttl_seconds(int(expires_in_seconds), self._ttl_cap_s)
                    self._cache.setex(key, ttl_s, json.dumps(cached_doc))
                except Exception:
                    pass
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
            result: Optional[Dict[str, Any]] = None
            # Try in-process LRU first
            key = self._cache_key(session_id)
            # 1) LRU
            session_data = self._lru.get(key)
            if session_data is not None:
                current_time = int(time.time() * 1000)
                if session_data.get('expires_at', 0) > current_time:
                    session_data['id'] = session_id
                    result = session_data

            # 2) Redis/external cache
            if result is None and self._cache is not None:
                try:
                    cached = ensure_text(self._cache.get(key))
                    if cached:
                        session_data = json_loads_safe(cached)
                        if session_data is not None:
                            current_time = int(time.time() * 1000)
                            if session_data.get('expires_at', 0) > current_time:
                                session_data['id'] = session_id
                                self._lru.set(key, session_data)
                                result = session_data
                except Exception:
                    result = None

            if result is None:
                doc_ref = self.collection.document(session_id)
                doc = doc_ref.get()
                if doc.exists:
                    session_data = doc.to_dict()
                    # Check if session is expired
                    current_time = int(time.time() * 1000)
                    if session_data.get('expires_at', 0) > current_time:
                        session_data['id'] = doc.id
                        # Write-through cache with remaining TTL
                        remaining_ms = max(0, int(session_data.get('expires_at', 0) - current_time))
                        ttl_s = cap_ttl_seconds(int(remaining_ms / 1000), self._ttl_cap_s)
                        self._lru.set(key, session_data)
                        if self._cache is not None:
                            try:
                                self._cache.setex(key, ttl_s, json_dumps_compact(session_data))
                            except Exception:
                                pass
                        result = session_data
                # If doc doesn't exist or expired -> result stays None
            return result
            
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
            
            # Refresh cached last_access without extending expiration
            key = self._cache_key(session_id)
            try:
                if self._cache is not None:
                    cached = ensure_text(self._cache.get(key))
                    if cached:
                        data = json_loads_safe(cached)
                        if data is not None:
                            data['last_access'] = current_time
                            try:
                                # type: ignore[attr-defined]
                                self._cache.set(key, json_dumps_compact(data), keepttl=True)
                            except Exception:
                                ttl = self._cache.ttl(key)
                                if ttl is None or ttl < 0:
                                    ttl = 1
                                self._cache.setex(key, cap_ttl_seconds(int(ttl), self._ttl_cap_s), json_dumps_compact(data))
            except Exception:
                pass
            # 1) Update LRU
            hit = self._lru.get(key)
            if hit:
                hit['last_access'] = current_time
                self._lru.set(key, hit)
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
            success = False
            doc_ref = self.collection.document(session_id)
            doc_ref.delete()
            
            # Invalidate cache
            key = self._cache_key(session_id)
            # 1) LRU
            self._lru.delete(key)
            # 2) Redis
            if self._cache is not None:
                try:
                    self._cache.delete(key)
                except Exception:
                    pass
            logger.info(f"Invalidated session {session_id}")
            success = True
            return success
            
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

                # Invalidate cache per session
                key = self._cache_key(session_id)
                # 1) LRU
                self._lru.delete(key)
                # 2) Redis
                if self._cache is not None:
                    try:
                        self._cache.delete(key)
                    except Exception:
                        pass
                
            logger.info(f"Invalidated {invalidated_count} sessions for user {user_id}")
            result = invalidated_count
            return result
            
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
            new_id: Optional[str] = None
            # Create new session
            new_session_id = self.create_session(
                user_id, username, role, expires_in_seconds, request_info
            )
            
            if new_session_id:
                # Invalidate old session
                self.invalidate_session(old_session_id)
                logger.info(f"Rotated session {old_session_id} to {new_session_id}")
                new_id = new_session_id
            return new_id
            
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
                # Remove cache entry
                # 1) LRU
                try:
                    self._lru.delete(self._cache_key(doc.id))
                except Exception:
                    pass
                # 2) Redis
                if self._cache is not None:
                    try:
                        self._cache.delete(self._cache_key(doc.id))
                    except Exception:
                        pass
                
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
                
            result = cleaned_count
            return result
            
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
