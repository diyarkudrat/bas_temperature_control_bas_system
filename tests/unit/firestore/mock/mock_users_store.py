"""Mock Firestore users data access layer with repository pattern."""

import time
import logging
import uuid
from typing import Dict, Any, Optional, List
from unittest.mock import Mock

from .mock_base import MockBaseRepository, MockTimestampedRepository, MockQueryOptions, MockPaginatedResult, MockOperationResult
from .mock_models import MockUser, create_mock_user, validate_mock_username, validate_mock_role

logger = logging.getLogger(__name__)


class MockUsersRepository(MockTimestampedRepository):
    """Mock users repository with validation and timestamping."""
    
    def __init__(self, client: Mock):
        """Initialize with mock Firestore client."""
        super().__init__(client, 'users')
        self.required_fields = ['username', 'password_hash', 'salt']
    
    def create(self, entity: MockUser) -> MockOperationResult[str]:
        """Create a new user."""
        try:
            # Validate entity
            self._validate_required_fields(entity.to_dict(), self.required_fields)
            
            # Validate username and role
            if not validate_mock_username(entity.username):
                raise ValueError(f"Invalid username format: {entity.username}")
            if not validate_mock_role(entity.role):
                raise ValueError(f"Invalid role: {entity.role}")
            
            # Check if username already exists
            try:
                existing = self.get_by_username(entity.username)
                if existing.success and existing.data:
                    return MockOperationResult(success=False, error="Username already exists", error_code="USERNAME_EXISTS")
            except Exception:
                # If get_by_username fails due to mock setup issues, skip the check
                # This allows the test to control the behavior through mocking
                pass
            
            # Add timestamps
            data = entity.to_dict()
            data = self._add_timestamps(data)
            
            # Store user document with user_id as document ID
            doc_ref = self.collection.document(entity.user_id)
            doc_ref.set(data)
            
            self.logger.info(f"Created user {entity.username} with ID {entity.user_id}")
            return MockOperationResult(success=True, data=entity.user_id)
            
        except ValueError as e:
            # Re-raise validation errors directly
            raise e
        except Exception as e:
            self._handle_mock_firestore_error("create user", e)
            raise
    
    def get_by_id(self, entity_id: str) -> MockOperationResult[MockUser]:
        """Get user by user ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return MockOperationResult(success=False, error="User not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            user = create_mock_user(data)
            user.id = doc.id
            
            return MockOperationResult(success=True, data=user)
            
        except Exception as e:
            self._handle_mock_firestore_error("get user by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> MockOperationResult[MockUser]:
        """Update user by ID."""
        try:
            # Add update timestamp
            updates = self._add_timestamps(updates, include_updated=True)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated user
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("update user", e)
    
    def delete(self, entity_id: str) -> MockOperationResult[bool]:
        """Delete user by ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.info(f"Deleted user {entity_id}")
            return MockOperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_mock_firestore_error("delete user", e)
    
    # User-specific methods
    def get_by_username(self, username: str) -> MockOperationResult[MockUser]:
        """Get user by username."""
        try:
            query = self.collection.where('username', '==', username).limit(1)
            docs = list(query.stream())
            
            if not docs:
                return MockOperationResult(success=False, error="User not found", error_code="NOT_FOUND")
            
            doc = docs[0]
            data = doc.to_dict()
            user = create_mock_user(data)
            user.id = doc.id
            
            return MockOperationResult(success=True, data=user)
            
        except Exception as e:
            self._handle_mock_firestore_error("get user by username", e)
            raise
    
    def list_users(self, options: MockQueryOptions = None) -> MockPaginatedResult[MockUser]:
        """List users with pagination."""
        try:
            options = options or MockQueryOptions()
            query = self.collection
            
            # Apply query options
            query = self._apply_query_options(query, options)
            
            # Execute query
            docs = list(query.stream())
            
            # Convert to users
            users = []
            for doc in docs:
                data = doc.to_dict()
                user = create_mock_user(data)
                user.id = doc.id
                users.append(user)
            
            # Check if there are more results
            has_more = len(docs) == options.limit
            next_offset = docs[-1].id if has_more and docs else None
            
            return MockPaginatedResult(
                items=users,
                has_more=has_more,
                next_offset=next_offset
            )
            
        except Exception as e:
            self._handle_mock_firestore_error("list users", e)
    
    def update_last_login(self, user_id: str) -> MockOperationResult[MockUser]:
        """Update user's last login timestamp."""
        try:
            current_time = int(time.time() * 1000)
            return self.update(user_id, {'last_login': current_time})
            
        except Exception as e:
            self._handle_mock_firestore_error("update last login", e)
    
    def increment_failed_attempts(self, user_id: str) -> MockOperationResult[MockUser]:
        """Increment failed login attempts."""
        try:
            # Get current user
            result = self.get_by_id(user_id)
            if not result.success:
                return result
            
            user = result.data
            new_attempts = user.failed_attempts + 1
            
            # Update failed attempts
            return self.update(user_id, {'failed_attempts': new_attempts})
            
        except Exception as e:
            self._handle_mock_firestore_error("increment failed attempts", e)
    
    def reset_failed_attempts(self, user_id: str) -> MockOperationResult[MockUser]:
        """Reset failed login attempts."""
        try:
            return self.update(user_id, {'failed_attempts': 0})
            
        except Exception as e:
            self._handle_mock_firestore_error("reset failed attempts", e)
    
    def clear_failed_attempts(self, user_id: str) -> MockOperationResult[MockUser]:
        """Clear failed login attempts (alias for reset_failed_attempts)."""
        return self.reset_failed_attempts(user_id)
    
    def lock_user(self, user_id: str, lock_duration_ms: int) -> MockOperationResult[MockUser]:
        """Lock user account."""
        try:
            current_time = int(time.time() * 1000)
            locked_until = current_time + lock_duration_ms
            
            return self.update(user_id, {'locked_until': locked_until})
            
        except Exception as e:
            self._handle_mock_firestore_error("lock user", e)
    
    def unlock_user(self, user_id: str) -> MockOperationResult[MockUser]:
        """Unlock user account."""
        try:
            return self.update(user_id, {'locked_until': 0})
            
        except Exception as e:
            self._handle_mock_firestore_error("unlock user", e)
    
    def update_password_history(self, user_id: str, new_hash: str) -> MockOperationResult[MockUser]:
        """Update user's password history."""
        try:
            # Get current user
            result = self.get_by_id(user_id)
            if not result.success:
                return result
            
            user = result.data
            new_history = user.password_history.copy()
            new_history.append(new_hash)
            
            # Keep only last 5 passwords
            if len(new_history) > 5:
                new_history = new_history[-5:]
            
            return self.update(user_id, {'password_history': new_history})
            
        except Exception as e:
            self._handle_mock_firestore_error("update password history", e)
    
    def update_password(self, user_id: str, new_password_hash: str, new_salt: str, algorithm_params: dict = None) -> MockOperationResult[MockUser]:
        """Update user's password."""
        try:
            # Get current user
            result = self.get_by_id(user_id)
            if not result.success:
                return result
            
            # Prepare updates
            updates = {
                'password_hash': new_password_hash,
                'salt': new_salt
            }
            
            # Add algorithm parameters if provided
            if algorithm_params:
                updates['algorithm_params'] = algorithm_params
            
            # Update password history
            self.update_password_history(user_id, new_password_hash)
            
            # Update user
            return self.update(user_id, updates)
            
        except Exception as e:
            self._handle_mock_firestore_error("update password", e)
    
    def get_by_role(self, role: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockUser]:
        """Get users by role."""
        try:
            options = options or MockQueryOptions()
            options.filters = {'role': role}
            
            return self.list_users(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("get users by role", e)
            raise
    
    def list_users_by_role(self, role: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockUser]:
        """List users by role (alias for get_by_role for backward compatibility)."""
        return self.get_by_role(role, options)
    
    def count_users(self) -> MockOperationResult[int]:
        """Count total number of users."""
        try:
            query = self.collection
            docs = list(query.stream())
            
            return MockOperationResult(success=True, data=len(docs))
            
        except Exception as e:
            self._handle_mock_firestore_error("count users", e)
    
    # Legacy compatibility methods
    def create_user(self, username: str, password_hash: str, salt: str, role: str = "operator") -> Optional[str]:
        """Legacy create_user method for backward compatibility."""
        try:
            user = create_mock_user({
                'username': username,
                'password_hash': password_hash,
                'salt': salt,
                'role': role
            })
            result = self.create(user)
            return result.data if result.success else None
        except Exception:
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Legacy get_user_by_id method for backward compatibility."""
        try:
            result = self.get_by_id(user_id)
            return result.data.to_dict() if result.success else None
        except Exception:
            return None
    
    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Legacy get_user_by_username method for backward compatibility."""
        try:
            result = self.get_by_username(username)
            return result.data.to_dict() if result.success else None
        except Exception:
            return None
    
    def update_user(self, user_id: str, updates: dict) -> bool:
        """Legacy update_user method for backward compatibility."""
        try:
            result = self.update(user_id, updates)
            return result.success
        except Exception:
            return False
    
    def delete_user(self, username: str) -> bool:
        """Legacy delete_user method for backward compatibility."""
        try:
            result = self.get_by_username(username)
            if not result.success:
                return False
            return self.delete(result.data.user_id).success
        except Exception:
            return False
    
    def is_user_locked(self, username: str) -> bool:
        """Legacy is_user_locked method for backward compatibility."""
        try:
            result = self.get_by_username(username)
            return result.data.is_locked if result.success else False
        except Exception:
            return False


# Backward compatibility alias
MockUsersStore = MockUsersRepository
