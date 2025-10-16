#!/usr/bin/env python3
"""Authentication administration tool."""

import argparse
import sys
import os
import json
import logging

# Add server directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'server'))

from auth import AuthConfig, UserManager
from auth.utils import validate_password_strength

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_user(db_path: str, username: str, password: str, phone_number: str, role: str = "operator"):
    """Create new user account."""
    logger.info(f"Creating user: {username} with role: {role}")
    
    config = AuthConfig()
    user_manager = UserManager(db_path, config)
    
    # Validate password
    is_valid, message = validate_password_strength(password)
    if not is_valid:
        logger.error(f"Password validation failed: {message}")
        return False
    
    try:
        user = user_manager.create_user(username, password, phone_number, role)
        logger.info(f"User {username} created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return False

def list_users(db_path: str):
    """List all users."""
    logger.info("Listing all users")
    
    config = AuthConfig()
    user_manager = UserManager(db_path, config)
    
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT username, role, created_at, last_login, failed_attempts, locked_until FROM users')
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            print("No users found")
            return
        
        print(f"{'Username':<20} {'Role':<10} {'Created':<20} {'Last Login':<20} {'Failed':<6} {'Status'}")
        print("-" * 100)
        
        for row in rows:
            username, role, created_at, last_login, failed_attempts, locked_until = row
            created_str = "Never" if created_at == 0 else str(int(created_at))
            last_login_str = "Never" if last_login == 0 else str(int(last_login))
            status = "Locked" if locked_until > 0 else "Active"
            
            print(f"{username:<20} {role:<10} {created_str:<20} {last_login_str:<20} {failed_attempts:<6} {status}")
            
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        return False

def reset_user_password(db_path: str, username: str, new_password: str):
    """Reset user password."""
    logger.info(f"Resetting password for user: {username}")
    
    config = AuthConfig()
    user_manager = UserManager(db_path, config)
    
    # Validate password
    is_valid, message = validate_password_strength(new_password)
    if not is_valid:
        logger.error(f"Password validation failed: {message}")
        return False
    
    try:
        user = user_manager.get_user(username)
        if not user:
            logger.error(f"User {username} not found")
            return False
        
        # Update password
        from auth.utils import hash_password
        password_hash, salt = hash_password(new_password)
        
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, locked_until = 0 WHERE username = ?',
            (password_hash, salt, username)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Password reset successfully for user {username}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to reset password: {e}")
        return False

def unlock_user(db_path: str, username: str):
    """Unlock user account."""
    logger.info(f"Unlocking user: {username}")
    
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?',
            (username,)
        )
        
        if cursor.rowcount == 0:
            logger.error(f"User {username} not found")
            conn.close()
            return False
        
        conn.commit()
        conn.close()
        
        logger.info(f"User {username} unlocked successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to unlock user: {e}")
        return False

def delete_user(db_path: str, username: str):
    """Delete user account."""
    logger.info(f"Deleting user: {username}")
    
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Delete user sessions first
        cursor.execute('DELETE FROM sessions WHERE username = ?', (username,))
        
        # Delete user
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        
        if cursor.rowcount == 0:
            logger.error(f"User {username} not found")
            conn.close()
            return False
        
        conn.commit()
        conn.close()
        
        logger.info(f"User {username} deleted successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='BAS Authentication Admin Tool')
    parser.add_argument('--db', default='server/bas_telemetry.db', help='Database path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create user command
    create_parser = subparsers.add_parser('create-user', help='Create new user')
    create_parser.add_argument('username', help='Username')
    create_parser.add_argument('password', help='Password')
    create_parser.add_argument('phone_number', help='Phone number (E.164 format)')
    create_parser.add_argument('--role', default='operator', choices=['operator', 'admin', 'read-only'], help='User role')
    
    # List users command
    subparsers.add_parser('list-users', help='List all users')
    
    # Reset password command
    reset_parser = subparsers.add_parser('reset-password', help='Reset user password')
    reset_parser.add_argument('username', help='Username')
    reset_parser.add_argument('new_password', help='New password')
    
    # Unlock user command
    unlock_parser = subparsers.add_parser('unlock-user', help='Unlock user account')
    unlock_parser.add_argument('username', help='Username')
    
    # Delete user command
    delete_parser = subparsers.add_parser('delete-user', help='Delete user account')
    delete_parser.add_argument('username', help='Username')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    success = False
    
    if args.command == 'create-user':
        success = create_user(args.db, args.username, args.password, args.phone_number, args.role)
    elif args.command == 'list-users':
        list_users(args.db)
        success = True
    elif args.command == 'reset-password':
        success = reset_user_password(args.db, args.username, args.new_password)
    elif args.command == 'unlock-user':
        success = unlock_user(args.db, args.username)
    elif args.command == 'delete-user':
        success = delete_user(args.db, args.username)
    else:
        parser.print_help()
        return
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
