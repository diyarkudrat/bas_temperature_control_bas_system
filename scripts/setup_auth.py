#!/usr/bin/env python3
"""Authentication setup script."""

import os
import sys
import json
import logging

# Add server directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'server'))

from auth import AuthConfig, UserManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_auth_config():
    """Setup authentication configuration."""
    logger.info("Setting up authentication configuration")
    
    config_path = 'config/auth_config.json'
    
    # Check if config already exists
    if os.path.exists(config_path):
        logger.info("Auth configuration already exists")
        return True
    
    # Create default config
    default_config = {
        "auth_enabled": True,
        "auth_mode": "user_password_mfa",
        "session_timeout": 1800,
        "max_concurrent_sessions": 3,
        "session_rotation": True,
        "mfa_code_expiry": 300,
        "mfa_code_length": 6,
        "sms_provider": "twilio",
        "max_login_attempts": 5,
        "lockout_duration": 900,
        "password_min_length": 12,
        "password_history_count": 5,
        "rate_limit_per_ip": 100,
        "rate_limit_per_user": 50,
        "auth_attempts_per_15min": 5
    }
    
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        logger.info(f"Auth configuration created: {config_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create auth config: {e}")
        return False

def setup_database():
    """Setup authentication database tables."""
    logger.info("Setting up authentication database")
    
    db_path = 'server/bas_telemetry.db'
    
    try:
        config = AuthConfig()
        user_manager = UserManager(db_path, config)
        logger.info("Database tables initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup database: {e}")
        return False

def create_admin_user():
    """Create initial admin user."""
    logger.info("Creating initial admin user")
    
    db_path = 'server/bas_telemetry.db'
    
    try:
        config = AuthConfig()
        user_manager = UserManager(db_path, config)
        
        # Check if admin user already exists
        if user_manager.get_user('admin'):
            logger.info("Admin user already exists")
            return True
        
        # Create admin user with default password
        admin_password = 'Admin123!@#X'
        admin_phone = '+1234567890'  # Default phone - should be changed
        
        user_manager.create_user('admin', admin_password, admin_phone, 'admin')
        
        logger.warning("=" * 60)
        logger.warning("IMPORTANT: Default admin user created!")
        logger.warning("Username: admin")
        logger.warning("Password: Admin123!@#X")
        logger.warning("Phone: +1234567890")
        logger.warning("Please change these credentials immediately!")
        logger.warning("=" * 60)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {e}")
        return False

def check_twilio_config():
    """Check Twilio configuration."""
    logger.info("Checking Twilio configuration")
    
    config_path = 'config/secrets.json'
    
    if not os.path.exists(config_path):
        logger.warning("Secrets file not found. Please create config/secrets.json with Twilio credentials")
        return False
    
    try:
        with open(config_path, 'r') as f:
            secrets = json.load(f)
        
        twilio_config = secrets.get('twilio', {})
        
        if not all([twilio_config.get('account_sid'), twilio_config.get('auth_token'), twilio_config.get('from_number')]):
            logger.warning("Twilio configuration incomplete in secrets.json")
            logger.warning("Please add Twilio credentials to config/secrets.json")
            return False
        
        logger.info("Twilio configuration found")
        return True
        
    except Exception as e:
        logger.error(f"Failed to check Twilio config: {e}")
        return False

def main():
    logger.info("Starting BAS Authentication Setup")
    
    success = True
    
    # Setup configuration
    if not setup_auth_config():
        success = False
    
    # Setup database
    if not setup_database():
        success = False
    
    # Create admin user
    if not create_admin_user():
        success = False
    
    # Check Twilio config
    twilio_ok = check_twilio_config()
    
    if success:
        logger.info("Authentication setup completed successfully")
        
        if not twilio_ok:
            logger.warning("SMS functionality will not work without Twilio configuration")
        
        logger.info("Next steps:")
        logger.info("1. Update Twilio credentials in config/secrets.json")
        logger.info("2. Change default admin password")
        logger.info("3. Create additional users as needed")
        logger.info("4. Start the server with authentication enabled")
    else:
        logger.error("Authentication setup failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
