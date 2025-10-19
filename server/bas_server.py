#!/usr/bin/env python3
"""
BAS Server - Computer-based control system for Pico W clients
Handles web interface, database, and control logic
"""

import json
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, g
from flask_cors import CORS
import logging

# Authentication imports
from auth import (
    AuthConfig, UserManager, SessionManager,
    AuditLogger, RateLimiter,
    require_auth, add_security_headers
)

# Firestore imports
from services.firestore.service_factory import get_service_factory
from auth.tenant_middleware import TenantMiddleware

# Alerting imports
from services.alerting import AlertService
from models.alert import Alert, AlertSeverity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

class BASController:
    """Temperature control logic."""
    
    def __init__(self):
        self.setpoint_tenths = 230  # 23.0°C
        self.deadband_tenths = 10   # 1.0°C
        self.min_on_time_ms = 10000  # 10 seconds
        self.min_off_time_ms = 10000  # 10 seconds
        
        # State tracking
        self.last_cool_on_time = 0
        self.last_cool_off_time = 0
        self.last_heat_on_time = 0
        self.last_heat_off_time = 0
        
        # Current status
        self.current_temp_tenths = 0
        self.sensor_ok = False
        self.cool_active = False
        self.heat_active = False
        self.state = "IDLE"
    
    def update_control(self, temp_tenths, sensor_ok):
        """Update control logic based on sensor reading."""
        self.current_temp_tenths = temp_tenths
        self.sensor_ok = sensor_ok
        
        if not sensor_ok:
            # Sensor fault - turn off all actuators
            self.cool_active = False
            self.heat_active = False
            self.state = "FAULT"
            return
        
        current_time = time.time() * 1000  # milliseconds
        
        # Determine if we should cool
        should_cool = temp_tenths > (self.setpoint_tenths + self.deadband_tenths)
        
        # LED strips (heating relay) are always on
        self.heat_active = True
        
        # Apply minimum on/off times for cooling only
        if self.cool_active:
            if not should_cool and (current_time - self.last_cool_on_time) >= self.min_on_time_ms:
                self.cool_active = False
                self.last_cool_off_time = current_time
            elif should_cool:
                # Keep cooling
                pass
        else:
            if should_cool and (current_time - self.last_cool_off_time) >= self.min_off_time_ms:
                self.cool_active = True
                self.last_cool_on_time = current_time
        
        # Update state
        if self.cool_active and self.heat_active:
            self.state = "COOLING_WITH_LEDS"
        elif self.cool_active:
            self.state = "COOLING"
        elif self.heat_active:
            self.state = "IDLE_WITH_LEDS"
        else:
            self.state = "IDLE"
    
    def get_control_commands(self):
        """Get current control commands for Pico client."""
        return {
            "cool_active": self.cool_active,
            "heat_active": self.heat_active,
            "setpoint_tenths": self.setpoint_tenths,
            "deadband_tenths": self.deadband_tenths
        }
    
    def set_setpoint(self, setpoint_tenths):
        """Set temperature setpoint."""
        if 100 <= setpoint_tenths <= 400:  # 10.0°C to 40.0°C
            self.setpoint_tenths = setpoint_tenths
            return True
        return False
    
    def set_deadband(self, deadband_tenths):
        """Set temperature deadband."""
        if 0 <= deadband_tenths <= 50:  # 0.0°C to 5.0°C
            self.deadband_tenths = deadband_tenths
            return True
        return False

class BASDatabase:
    """SQLite database for telemetry data."""
    
    def __init__(self, db_path="bas_telemetry.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                temp_tenths INTEGER,
                setpoint_tenths INTEGER,
                deadband_tenths INTEGER,
                cool_active BOOLEAN,
                heat_active BOOLEAN,
                state TEXT,
                sensor_ok BOOLEAN
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON telemetry(timestamp)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def store_data(self, data):
        """Store telemetry data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO telemetry 
            (timestamp, temp_tenths, setpoint_tenths, deadband_tenths, 
             cool_active, heat_active, state, sensor_ok)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('timestamp', time.time() * 1000),
            data.get('temp_tenths', 0),
            data.get('setpoint_tenths', 230),
            data.get('deadband_tenths', 10),
            data.get('cool_active', False),
            data.get('heat_active', False),
            data.get('state', 'IDLE'),
            data.get('sensor_ok', False)
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_data(self, limit=100):
        """Get recent telemetry data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, temp_tenths, setpoint_tenths, deadband_tenths,
                   cool_active, heat_active, state, sensor_ok
            FROM telemetry 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        data = []
        for row in rows:
            data.append({
                'timestamp': row[0],
                'temp_tenths': row[1],
                'setpoint_tenths': row[2],
                'deadband_tenths': row[3],
                'cool_active': bool(row[4]),
                'heat_active': bool(row[5]),
                'state': row[6],
                'sensor_ok': bool(row[7])
            })
        
        return data

# Global instances
controller = BASController()
database = BASDatabase()

# Authentication global variables
auth_config = None
user_manager = None
session_manager = None
audit_logger = None
rate_limiter = None

# Firestore / Alerting global variables
firestore_factory = None
tenant_middleware = None
alert_service = AlertService()
# Simple event hook registry
_event_hooks = {}

def init_auth():
    """Initialize authentication system."""
    global auth_config, user_manager, session_manager
    global audit_logger, rate_limiter
    global firestore_factory, tenant_middleware
    
    try:
        logger.info("Initializing authentication system")
        
        # Load auth configuration
        auth_config = AuthConfig.from_file('config/auth_config.json')
        if not auth_config.validate():
            logger.error("Invalid auth configuration")
            return False
        
        # Initialize Firestore if enabled
        if any([auth_config.use_firestore_telemetry, auth_config.use_firestore_auth, auth_config.use_firestore_audit]):
            logger.info("Initializing Firestore services")
            firestore_factory = get_service_factory(auth_config)
            
            # Health check
            health = firestore_factory.health_check()
            if health['status'] != 'healthy':
                logger.error(f"Firestore health check failed: {health}")
                return False
            
            logger.info("Firestore services initialized successfully")
        
        # Initialize tenant middleware if Firestore is enabled
        if firestore_factory:
            tenant_middleware = TenantMiddleware(auth_config, firestore_factory)
            logger.info("Tenant middleware initialized")
        
        # Initialize managers (will use Firestore if enabled)
        user_manager = UserManager(database.db_path, auth_config, firestore_factory)
        session_manager = SessionManager(database.db_path, auth_config, firestore_factory)
        
        # Initialize services
        audit_logger = AuditLogger(database.db_path, firestore_factory)
        rate_limiter = RateLimiter(auth_config)
        _init_alerting_service()
        
        logger.info("Authentication system initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize auth system: {e}")
        return False

def _init_alerting_service():
    """Initialize alerting; safe no-op if env/config is absent."""
    try:
        alert_service.init_twilio()
        logger.info("Alerting service initialized")
    except Exception as e:
        logger.info(f"Alerting not initialized (skipped): {e}")

def add_event_hook(event_name, callback):
    """Register a callback for a named event."""
    hooks = _event_hooks.setdefault(event_name, [])
    hooks.append(callback)

def _trigger_event(event_name, payload):
    """Invoke registered callbacks for an event (best-effort)."""
    for cb in _event_hooks.get(event_name, []):
        try:
            cb(payload)
        except Exception as e:
            logger.warning(f"Event hook error for {event_name}: {e}")

def _trigger_alert(message, severity="error", *, sms_to=None, email_to=None, subject=None, metadata=None):
    """Lightweight alert trigger; logs and continues on failure."""
    try:
        alert = Alert(
            message=message,
            severity=AlertSeverity.from_string(severity),
            sms_to=list(sms_to or []),
            email_to=list(email_to or []),
            subject=subject,
            tenant_id=getattr(g, 'tenant_id', None),
            metadata=metadata or {},
        )
        # Prefer SMS when provided; otherwise log email intention (no SMTP config wired here)
        for dest in alert.sms_to:
            alert_service.send_sms(to_number=dest, body=alert.message)
        if alert.email_to:
            logger.info("Email targets present but no email_config provided; skipping email send")
        logger.info("Alert triggered: %s (%s)", alert.message, alert.severity.value)
        return True
    except Exception as e:
        logger.error("Failed to trigger alert: %s", e)
        return False

def _build_telemetry_payload(data):
    return {
        'timestamp': data.get('timestamp', time.time() * 1000),
        'temp_tenths': data.get('temp_tenths', 0),
        'sensor_ok': data.get('sensor_ok', False),
        'setpoint_tenths': controller.setpoint_tenths,
        'deadband_tenths': controller.deadband_tenths,
        'cool_active': controller.cool_active,
        'heat_active': controller.heat_active,
        'state': controller.state
    }

def _store_telemetry_with_fallback(telemetry_data, data):
    """Store telemetry in Firestore when enabled; fallback to SQLite."""
    if firestore_factory and firestore_factory.is_telemetry_enabled():
        try:
            tenant_id = getattr(g, 'tenant_id', 'default')
            device_id = data.get('device_id', 'unknown')
            telemetry_service = firestore_factory.get_telemetry_service()
            telemetry_service.add_telemetry(
                tenant_id=tenant_id,
                device_id=device_id,
                timestamp_ms=int(telemetry_data['timestamp']),
                temp_tenths=telemetry_data['temp_tenths'],
                setpoint_tenths=telemetry_data['setpoint_tenths'],
                deadband_tenths=telemetry_data['deadband_tenths'],
                cool_active=telemetry_data['cool_active'],
                heat_active=telemetry_data['heat_active'],
                state=telemetry_data['state'],
                sensor_ok=telemetry_data['sensor_ok']
            )
            logger.debug(f"Stored telemetry in Firestore for tenant={tenant_id}, device={device_id}")
            return
        except Exception as e:
            logger.error(f"Failed to store telemetry in Firestore: {e}")
    database.store_data(telemetry_data)

def _handle_sensor_fault_alert(data, telemetry_data):
    if telemetry_data.get('sensor_ok'):
        return
    payload = {"device_id": data.get('device_id', 'unknown')}
    _trigger_event('sensor_fault', payload)
    _trigger_alert("Sensor fault detected on device", severity="error", metadata=payload)

@app.route('/')
def dashboard():
    """Main dashboard."""
    return render_template('dashboard.html')

@app.route('/auth/login')
def auth_login_page():
    """Login page."""
    return render_template('auth/login.html')


@app.route('/api/health')
def health():
    """Health check endpoint."""
    health_status = {
        "status": "healthy", 
        "timestamp": time.time(),
        "services": {
            "auth": bool(auth_config is not None),
            "firestore": bool(firestore_factory is not None)
        }
    }
    
    # Add Firestore health if available
    if firestore_factory:
        try:
            firestore_health = firestore_factory.health_check()
            # Ensure JSON-safe primitives
            if isinstance(firestore_health, dict):
                safe_health = {}
                for k, v in firestore_health.items():
                    try:
                        json.dumps(v)
                        safe_health[k] = v
                    except Exception:
                        safe_health[k] = str(v)
                health_status["firestore"] = safe_health
            else:
                # Fallback to string representation
                health_status["firestore"] = str(firestore_health)
        except Exception as e:
            logger.error(f"Error retrieving Firestore health: {e}")
            health_status["firestore"] = {"status": "error", "detail": str(e)}
    
    return jsonify(health_status)

@app.route('/api/sensor_data', methods=['POST'])
def receive_sensor_data():
    """Receive sensor data from Pico client."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data received"}), 400
        
        # Update controller
        controller.update_control(
            data.get('temp_tenths', 0),
            data.get('sensor_ok', False)
        )
        
        # Build telemetry payload
        telemetry_data = _build_telemetry_payload(data)
        
        # Hooks and alerts (non-blocking best-effort)
        _handle_sensor_fault_alert(data, telemetry_data)

        # Store with fallback
        _store_telemetry_with_fallback(telemetry_data, data)
        
        # Return control commands
        commands = controller.get_control_commands()
        return jsonify(commands)
        
    except Exception as e:
        logger.error(f"Error processing sensor data: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/status')
def get_status():
    """Get current system status."""
    return jsonify({
        "temp_tenths": controller.current_temp_tenths,
        "setpoint_tenths": controller.setpoint_tenths,
        "deadband_tenths": controller.deadband_tenths,
        "state": controller.state,
        "cool_active": controller.cool_active,
        "heat_active": controller.heat_active,
        "sensor_ok": controller.sensor_ok,
        "timestamp": time.time() * 1000
    })

@app.route('/api/set_setpoint', methods=['POST'])
@require_auth(required_role="operator")
def set_setpoint():
    """Set temperature setpoint - now requires authentication."""
    try:
        logger.info(f"Setpoint change request from {getattr(request, 'session', None).username if hasattr(getattr(request, 'session', None), 'username') else 'unknown'}")
        data = request.get_json()
        setpoint = data.get('setpoint_tenths')
        deadband = data.get('deadband_tenths')
        
        if setpoint is not None:
            if not controller.set_setpoint(setpoint):
                logger.warning(f"Invalid setpoint value: {setpoint}")
                return jsonify({"error": "Invalid setpoint"}), 400
        
        if deadband is not None:
            if not controller.set_deadband(deadband):
                logger.warning(f"Invalid deadband value: {deadband}")
                return jsonify({"error": "Invalid deadband"}), 400
        
        # Log the change with user info
        user_info = f"User: {request.session.username}" if hasattr(request, 'session') else "Unknown"
        logger.info(f"Setpoint updated by {user_info}: sp={setpoint}, db={deadband}")
        
        return jsonify({
            "success": True,
            "setpoint_tenths": controller.setpoint_tenths,
            "deadband_tenths": controller.deadband_tenths,
            "updated_by": request.session.username if hasattr(request, 'session') else "system"
        })
        
    except Exception as e:
        logger.error(f"Error setting setpoint: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/telemetry')
@require_auth(required_role="read-only")
def get_telemetry():
    """Get telemetry data - now requires authentication."""
    try:
        logger.debug(f"Telemetry request from {getattr(request, 'session', None).username if hasattr(getattr(request, 'session', None), 'username') else 'unknown'}")
        limit = request.args.get('limit', 100, type=int)
        device_id = request.args.get('device_id', 'unknown')
        
        # Get data from appropriate source based on feature flags
        if firestore_factory and firestore_factory.is_telemetry_enabled():
            try:
                tenant_id = getattr(g, 'tenant_id', 'default')
                telemetry_service = firestore_factory.get_telemetry_service()
                
                # Query recent telemetry with tenant isolation
                data = telemetry_service.query_recent(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    limit=limit
                )
                logger.debug(f"Retrieved {len(data)} telemetry records from Firestore")
            except Exception as e:
                logger.error(f"Failed to get telemetry from Firestore: {e}")
                # Fallback to SQLite
                data = database.get_recent_data(limit)
        else:
            # Use SQLite when Firestore is disabled
            data = database.get_recent_data(limit)
        
        return jsonify(data)
        
    except Exception as e:
        logger.error(f"Error getting telemetry: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/config')
def get_config():
    """Get system configuration."""
    config_payload = {
        "setpoint_tenths": int(controller.setpoint_tenths),
        "deadband_tenths": int(controller.deadband_tenths),
        "min_on_time_ms": int(controller.min_on_time_ms),
        "min_off_time_ms": int(controller.min_off_time_ms)
    }
    return jsonify(config_payload)

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Authenticate user with username/password."""
    if not auth_config or not auth_config.auth_enabled:
        logger.warning("Authentication attempt while auth disabled")
        return jsonify({"error": "Authentication disabled"}), 503
    
    try:
        logger.info("Authentication login attempt")
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            logger.warning("Missing required fields in login request")
            return jsonify({"error": "Missing required fields", "code": "MISSING_FIELDS"}), 400
        
        # Rate limiting check
        allowed, message = rate_limiter.is_allowed(request.remote_addr, username)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {username} from {request.remote_addr}")
            audit_logger.log_auth_failure(username, request.remote_addr, "RATE_LIMITED")
            return jsonify({"error": message, "code": "RATE_LIMITED"}), 429
        
        # User authentication
        user = user_manager.authenticate_user(username, password)
        if not user:
            logger.warning(f"Authentication failed for {username} from {request.remote_addr}")
            rate_limiter.record_attempt(request.remote_addr, username)
            audit_logger.log_auth_failure(username, request.remote_addr, "INVALID_CREDENTIALS")
            return jsonify({"error": "Invalid credentials", "code": "AUTH_FAILED"}), 401
        
        # Check if account is locked
        if user.is_locked():
            logger.warning(f"Login attempt on locked account: {username}")
            audit_logger.log_auth_failure(username, request.remote_addr, "ACCOUNT_LOCKED")
            return jsonify({"error": "Account locked", "code": "USER_LOCKED"}), 423
        
        # Create session directly
        logger.info(f"Creating session for {username}")
        
        # Create session
        session = session_manager.create_session(username, user.role, request)
        
        # Update user login time
        user_manager.update_last_login(username)
        
        # Clear rate limiting for successful auth
        rate_limiter.clear_attempts(request.remote_addr, username)
        
        # Audit log
        audit_logger.log_auth_success(username, request.remote_addr, session.session_id)
        
        logger.info(f"Authentication successful for {username}")
        
        # Create response with httpOnly cookie
        response = jsonify({
            "status": "success",
            "expires_in": auth_config.session_timeout,
            "user": {"username": username, "role": user.role}
        })
        
        # Set httpOnly cookie for session
        response.set_cookie(
            'bas_session_id', 
            session.session_id, 
            max_age=auth_config.session_timeout,
            httponly=True,
            secure=True,  # Only over HTTPS in production
            samesite='Strict'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in auth login: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    """Terminate user session."""
    try:
        logger.info("Logout request")
        
        # Get session ID from cookie or request body
        session_id = request.cookies.get('bas_session_id')
        if not session_id:
            data = request.get_json() or {}
            session_id = data.get('session_id')
        
        if session_id:
            if session_manager is not None:
                session_manager.invalidate_session(session_id)
            if audit_logger is not None:
                audit_logger.log_session_destruction(session_id)
            logger.info(f"Session invalidated: {session_id[:12]}...")
        
        # Create response and clear cookie
        response = jsonify({"status": "success", "message": "Logged out successfully"})
        response.set_cookie('bas_session_id', '', max_age=0, httponly=True, secure=True, samesite='Strict')
        
        return response
        
    except Exception as e:
        logger.error(f"Error in auth logout: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/auth/status')
def auth_status():
    """Check session validity and get user info."""
    session_id = request.cookies.get('bas_session_id') or request.headers.get('X-Session-ID')
    
    if not session_id:
        logger.warning("Auth status check without session ID")
        return jsonify({"error": "No session provided", "code": "NO_SESSION"}), 400
    
    session = session_manager.validate_session(session_id, request)
    if not session:
        logger.warning(f"Invalid session in status check: {session_id[:12]}...")
        return jsonify({"error": "Invalid or expired session", "code": "SESSION_INVALID"}), 401
    
    logger.debug(f"Session status check successful for {session.username}")
    return jsonify({
        "status": "valid",
        "user": {
            "username": session.username,
            "role": session.role,
            "login_time": session.created_at
        },
        "expires_in": int(session.expires_at - time.time())
    })

# Add request context setup
@app.before_request
def setup_auth_context():
    """Setup authentication context for each request."""
    if auth_config:
        request.auth_config = auth_config
        request.session_manager = session_manager
        request.audit_logger = audit_logger
        
        # Initialize tenant context if middleware is available
        if tenant_middleware:
            tenant_middleware.setup_tenant_context(request)

# Apply security headers
app.after_request(add_security_headers)

def cleanup_old_data():
    """Clean up old telemetry data (keep last 7 days)."""
    while True:
        try:
            conn = sqlite3.connect(database.db_path)
            cursor = conn.cursor()
            
            # Delete data older than 7 days
            cutoff_time = (time.time() - 7 * 24 * 3600) * 1000
            cursor.execute('DELETE FROM telemetry WHERE timestamp < ?', (cutoff_time,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old telemetry records")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        
        # Run cleanup once per day
        time.sleep(24 * 3600)

if __name__ == '__main__':
    # Initialize authentication system
    if not init_auth():
        logger.warning("Authentication system initialization failed - running without auth")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()
    
    logger.info("Starting BAS Server...")
    logger.info("Dashboard available at: http://localhost:8080")
    logger.info("API available at: http://localhost:8080/api/")
    if auth_config and auth_config.auth_enabled:
        logger.info("Authentication system enabled")
        logger.info("Auth endpoints available at: http://localhost:8080/auth/")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
