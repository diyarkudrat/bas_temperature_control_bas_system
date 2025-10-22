"""Modern Firestore users data access layer with repository pattern."""

import time
import logging
import uuid
from typing import Dict, Any, Optional, List
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

from .base import BaseRepository, TimestampedRepository, QueryOptions, PaginatedResult, OperationResult, FirestoreClientBoundary
from .models import User, create_user, validate_username, validate_role

logger = logging.getLogger(__name__)


class UsersRepository(TimestampedRepository):
    """Modern users repository with validation and timestamping."""
    
    def __init__(self, client: FirestoreClientBoundary):
        """Initialize with Firestore client."""
        # Explicitly initialize base to avoid MRO issues
        BaseRepository.__init__(self, client, 'users')
        self.required_fields = ['username', 'password_hash', 'salt']
    
    def create(self, entity: User) -> OperationResult[str]:
        """Create a new user."""
        try:
            # Validate entity
            self._validate_required_fields(entity.to_dict(), self.required_fields)
            
            # Validate username and role
            if not validate_username(entity.username):
                raise ValueError(f"Invalid username format: {entity.username}")
            if not validate_role(entity.role):
                raise ValueError(f"Invalid role: {entity.role}")
            
            # Check if username already exists
            existing = self.get_by_username(entity.username)
            if existing.success and existing.data:
                return OperationResult(success=False, error="Username already exists", error_code="USERNAME_EXISTS")
            
            # Add timestamps
            data = entity.to_dict()
            data = self._add_timestamps(data)
            
            # Store user document with user_id as document ID
            doc_ref = self.collection.document(entity.user_id)
            doc_ref.set(data)
            
            self.logger.info(f"Created user {entity.username} with ID {entity.user_id}")
            return OperationResult(success=True, data=entity.user_id)
            
        except Exception as e:
            self._handle_firestore_error("create user", e)
    
    def get_by_id(self, entity_id: str) -> OperationResult[User]:
        """Get user by user ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return OperationResult(success=False, error="User not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            user = create_user(data)
            user.id = doc.id
            
            return OperationResult(success=True, data=user)
            
        except Exception as e:
            self._handle_firestore_error("get user by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> OperationResult[User]:
        """Update user by ID."""
        try:
            # Add update timestamp
            updates = self._add_timestamps(updates, include_updated=True)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated user
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_firestore_error("update user", e)
    
    def delete(self, entity_id: str) -> OperationResult[bool]:
        """Delete user by ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.info(f"Deleted user {entity_id}")
            return OperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_firestore_error("delete user", e)
    
    # User-specific methods
    def get_by_username(self, username: str) -> OperationResult[User]:
        """Get user by username."""
        try:
            query = self.collection.where('username', '==', username).limit(1)
            docs = query.stream()
            
            for doc in docs:
                data = doc.to_dict()
                user = create_user(data)
                user.id = doc.id
                return OperationResult(success=True, data=user)
            
            return OperationResult(success=False, error="User not found", error_code="NOT_FOUND")
            
        except Exception as e:
            self._handle_firestore_error("get user by username", e)
    
    def authenticate_user(self, username: str, password_hash: str) -> OperationResult[User]:
        """Authenticate user with username and password hash."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return OperationResult(success=False, error="User not found", error_code="USER_NOT_FOUND")
            
            user = user_result.data
            
            # Check if account is locked
            if user.is_locked:
                return OperationResult(success=False, error="Account locked", error_code="ACCOUNT_LOCKED")
            
            # Verify password hash
            if user.password_hash != password_hash:
                # Increment failed attempts
                self.increment_failed_attempts_by_id(user.user_id)
                return OperationResult(success=False, error="Invalid credentials", error_code="INVALID_CREDENTIALS")
            
            # Clear failed attempts on successful auth
            self.clear_failed_attempts_by_id(user.user_id)
            
            return OperationResult(success=True, data=user)
            
        except Exception as e:
            self._handle_firestore_error("authenticate user", e)
    
    def update_last_login_by_id(self, user_id: str) -> OperationResult[bool]:
        """Update user's last login timestamp."""
        try:
            current_time = int(time.time() * 1000)
            result = self.update(user_id, {'last_login': current_time})
            return OperationResult(success=result.success, data=result.success)
            
        except Exception as e:
            self._handle_firestore_error("update last login", e)
    
    def increment_failed_attempts_by_id(self, user_id: str) -> OperationResult[bool]:
        """Increment failed login attempts for user."""
        try:
            user_result = self.get_by_id(user_id)
            if not user_result.success or not user_result.data:
                return OperationResult(success=False, error="User not found")
            
            user = user_result.data
            new_count = user.failed_attempts + 1
            
            result = self.update(user_id, {'failed_attempts': new_count})
            return OperationResult(success=result.success, data=result.success)
            
        except Exception as e:
            self._handle_firestore_error("increment failed attempts", e)
    
    def clear_failed_attempts_by_id(self, user_id: str) -> OperationResult[bool]:
        """Clear failed login attempts for user."""
        try:
            result = self.update(user_id, {'failed_attempts': 0})
            return OperationResult(success=result.success, data=result.success)
            
        except Exception as e:
            self._handle_firestore_error("clear failed attempts", e)
    
    def lock_user_by_id(self, user_id: str, lock_until_ms: int) -> OperationResult[bool]:
        """Lock user account until specified time."""
        try:
            # Perform direct update without read-after-write to avoid requiring a valid document payload
            updates = self._add_timestamps({'locked_until': lock_until_ms}, include_updated=True)
            doc_ref = self.collection.document(user_id)
            doc_ref.update(updates)
            return OperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_firestore_error("lock user", e)
    
    def update_password_by_id(self, user_id: str, new_password_hash: str, new_salt: str,
                       algorithm_params: Optional[Dict] = None) -> OperationResult[bool]:
        """Update user password and add to history."""
        try:
            user_result = self.get_by_id(user_id)
            if not user_result.success or not user_result.data:
                return OperationResult(success=False, error="User not found")
            
            user = user_result.data
            
            # Get current password history
            password_history = user.password_history.copy()
            
            # Add current password to history (limit to last 5)
            if user.password_hash:
                password_history.insert(0, user.password_hash)
                password_history = password_history[:5]
            
            updates = {
                'password_hash': new_password_hash,
                'salt': new_salt,
                'password_history': password_history,
                'algorithm_params': algorithm_params or {}
            }
            
            result = self.update(user_id, updates)
            return OperationResult(success=result.success, data=result.success)
            
        except Exception as e:
            self._handle_firestore_error("update password", e)
    
    def list_users_by_role(self, role: str, options: QueryOptions = None) -> PaginatedResult[User]:
        """List users by role."""
        try:
            options = options or QueryOptions()
            options.filters = {'role': role}
            options.order_by = 'username'
            options.order_direction = 'ASCENDING'
            
            query = self._apply_query_options(self.collection, options)
            docs = query.stream()
            
            results = []
            for doc in docs:
                data = doc.to_dict()
                user = create_user(data)
                user.id = doc.id
                results.append(user)
            
            return PaginatedResult(
                items=results,
                has_more=len(results) == options.limit
            )
            
        except Exception as e:
            self._handle_firestore_error("list users by role", e)
    
    # Legacy compatibility methods
    def create_user(self, username: str, password_hash: str, salt: str, 
                   role: str = "operator", algorithm_params: Optional[Dict] = None) -> Optional[str]:
        """Legacy method for creating a user."""
        try:
            user = User(
                username=username,
                password_hash=password_hash,
                salt=salt,
                role=role,
                algorithm_params=algorithm_params or {}
            )
            
            result = self.create(user)
            return result.data if result.success else None
            
        except Exception as e:
            self.logger.error(f"Failed to create user: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Legacy method for getting user by ID."""
        try:
            result = self.get_by_id(user_id)
            if result.success and result.data:
                return result.data.to_dict()
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get user by ID: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Legacy method for getting user by username."""
        try:
            result = self.get_by_username(username)
            if result.success and result.data:
                return result.data.to_dict()
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get user by username: {e}")
            return None
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Legacy method for updating user."""
        try:
            result = self.update(user_id, updates)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to update user: {e}")
            return False
    
    def update_last_login(self, username: str) -> bool:
        """Legacy method for updating last login."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.update_last_login_by_id(user_result.data.user_id)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to update last login: {e}")
            return False
    
    def increment_failed_attempts(self, username: str) -> bool:
        """Legacy method for incrementing failed attempts."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.increment_failed_attempts_by_id(user_result.data.user_id)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to increment failed attempts: {e}")
            return False
    
    def clear_failed_attempts(self, username: str) -> bool:
        """Legacy method for clearing failed attempts."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.clear_failed_attempts_by_id(user_result.data.user_id)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to clear failed attempts: {e}")
            return False
    
    def lock_user(self, username: str, lock_until_ms: int) -> bool:
        """Legacy method for locking user."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.lock_user_by_id(user_result.data.user_id, lock_until_ms)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to lock user: {e}")
            return False
    
    def is_user_locked(self, username: str) -> bool:
        """Legacy method for checking if user is locked."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            return user_result.data.is_locked
            
        except Exception as e:
            self.logger.error(f"Failed to check if user is locked: {e}")
            return False
    
    def update_password(self, username: str, new_password_hash: str, new_salt: str,
                       algorithm_params: Optional[Dict] = None) -> bool:
        """Legacy method for updating password."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.update_password_by_id(user_result.data.user_id, new_password_hash, new_salt, algorithm_params)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to update password: {e}")
            return False
    
    def delete_user(self, username: str) -> bool:
        """Legacy method for deleting user."""
        try:
            user_result = self.get_by_username(username)
            if not user_result.success or not user_result.data:
                return False
            
            result = self.delete(user_result.data.user_id)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to delete user: {e}")
            return False


# Backward compatibility alias
UsersStore = UsersRepository
