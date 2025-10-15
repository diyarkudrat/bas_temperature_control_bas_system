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
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging

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

@app.route('/')
def dashboard():
    """Main dashboard."""
    return render_template('dashboard.html')

@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": time.time()})

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
        
        # Store in database
        telemetry_data = {
            'timestamp': data.get('timestamp', time.time() * 1000),
            'temp_tenths': data.get('temp_tenths', 0),
            'sensor_ok': data.get('sensor_ok', False),
            'setpoint_tenths': controller.setpoint_tenths,
            'deadband_tenths': controller.deadband_tenths,
            'cool_active': controller.cool_active,
            'heat_active': controller.heat_active,
            'state': controller.state
        }
        
        database.store_data(telemetry_data)
        
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
def set_setpoint():
    """Set temperature setpoint."""
    try:
        data = request.get_json()
        setpoint = data.get('setpoint_tenths')
        deadband = data.get('deadband_tenths')
        
        if setpoint is not None:
            if not controller.set_setpoint(setpoint):
                return jsonify({"error": "Invalid setpoint"}), 400
        
        if deadband is not None:
            if not controller.set_deadband(deadband):
                return jsonify({"error": "Invalid deadband"}), 400
        
        return jsonify({
            "success": True,
            "setpoint_tenths": controller.setpoint_tenths,
            "deadband_tenths": controller.deadband_tenths
        })
        
    except Exception as e:
        logger.error(f"Error setting setpoint: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/telemetry')
def get_telemetry():
    """Get telemetry data."""
    try:
        limit = request.args.get('limit', 100, type=int)
        data = database.get_recent_data(limit)
        return jsonify(data)
        
    except Exception as e:
        logger.error(f"Error getting telemetry: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/config')
def get_config():
    """Get system configuration."""
    return jsonify({
        "setpoint_tenths": controller.setpoint_tenths,
        "deadband_tenths": controller.deadband_tenths,
        "min_on_time_ms": controller.min_on_time_ms,
        "min_off_time_ms": controller.min_off_time_ms
    })

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
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()
    
    logger.info("Starting BAS Server...")
    logger.info("Dashboard available at: http://localhost:8080")
    logger.info("API available at: http://localhost:8080/api/")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
