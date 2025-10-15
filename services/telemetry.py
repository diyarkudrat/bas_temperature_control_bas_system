# services/telemetry.py
# Lightweight telemetry collection optimized for BAS controller on MicroPython
# Design principles:
# - Ring buffer for memory efficiency (no unbounded growth)
# - Simple data structures to minimize GC pressure  
# - Optional CSV persistence for long-term analysis
# - Aggregation functions for API consumption
# - Extensible for additional sensors, zones, and custom metrics

import time
import gc
from services import LoggerFactory

class TelemetryPoint:
    """
    Single telemetry data point with minimal memory footprint.
    
    Designed to be extensible - stores core fields plus custom data.
    Use 'custom_data' dict for additional metrics without modifying core structure.
    """
    __slots__ = ('timestamp_ms', 'temp_tenths', 'setpoint_tenths', 'cool_active', 
                 'heat_active', 'state', 'alarm', 'error_code', 'zone_id', 'custom_data')
    
    def __init__(self, timestamp_ms, temp_tenths, setpoint_tenths, cool_active, 
                 heat_active, state, alarm=False, error_code=0, zone_id=None, custom_data=None):
        self.timestamp_ms = timestamp_ms
        self.temp_tenths = temp_tenths  # None if sensor fault
        self.setpoint_tenths = setpoint_tenths
        self.cool_active = cool_active
        self.heat_active = heat_active
        self.state = state  # Controller FSM state
        self.alarm = alarm
        self.error_code = error_code
        self.zone_id = zone_id  # Optional: for multi-zone support
        self.custom_data = custom_data or {}  # Extensible: add any custom metrics
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        result = {
            'ts': self.timestamp_ms,
            't': self.temp_tenths,
            'sp': self.setpoint_tenths,
            'c': 1 if self.cool_active else 0,
            'h': 1 if self.heat_active else 0,
            's': self.state,
            'a': 1 if self.alarm else 0,
            'e': self.error_code
        }
        
        # Add zone_id if present (for multi-zone)
        if self.zone_id is not None:
            result['z'] = self.zone_id
        
        # Add custom data if present (for extensibility)
        if self.custom_data:
            result['custom'] = self.custom_data
        
        return result
    
    @classmethod
    def from_dict(cls, data):
        """Create from dictionary (for deserialization)."""
        return cls(
            timestamp_ms=data['ts'],
            temp_tenths=data['t'],
            setpoint_tenths=data['sp'],
            cool_active=bool(data['c']),
            heat_active=bool(data['h']),
            state=data['s'],
            alarm=bool(data.get('a', 0)),
            error_code=data.get('e', 0),
            zone_id=data.get('z'),
            custom_data=data.get('custom')
        )


class TelemetryBuffer:
    """
    Fixed-size ring buffer for telemetry points.
    
    Design rationale: 
    - Fixed size prevents unbounded memory growth on long-running systems
    - Ring buffer allows efficient O(1) append and bounded memory
    - Default 1000 points @ 2s = ~33 minutes of history (reasonable for web graphs)
    """
    
    def __init__(self, capacity=1000):
        self._capacity = capacity
        self._buffer = [None] * capacity
        self._index = 0
        self._size = 0
        self._dropped_points = 0  # Track overflow for monitoring
    
    def append(self, point):
        """Add telemetry point to buffer."""
        if self._buffer[self._index] is not None:
            self._dropped_points += 1
        
        self._buffer[self._index] = point
        self._index = (self._index + 1) % self._capacity
        if self._size < self._capacity:
            self._size += 1
    
    def get_recent(self, count=None, start_time_ms=None):
        """
        Get recent points (newest first).
        
        Args:
            count: Maximum number of points to return
            start_time_ms: Only return points after this timestamp
        
        Returns:
            List of TelemetryPoint objects (newest first)
        """
        if count is None:
            count = self._size
        
        count = min(count, self._size)
        if count == 0:
            return []
        
        points = []
        idx = (self._index - 1) % self._capacity
        
        for _ in range(count):
            point = self._buffer[idx]
            if point is None:
                break
            
            # Time filtering
            if start_time_ms is not None and point.timestamp_ms < start_time_ms:
                break
            
            points.append(point)
            idx = (idx - 1) % self._capacity
        
        return points
    
    def get_all_chronological(self):
        """Get all points in chronological order (oldest first)."""
        if self._size == 0:
            return []
        
        # Determine starting index (oldest point)
        if self._size < self._capacity:
            start_idx = 0
        else:
            start_idx = self._index
        
        points = []
        for i in range(self._size):
            idx = (start_idx + i) % self._capacity
            if self._buffer[idx] is not None:
                points.append(self._buffer[idx])
        
        return points
    
    def clear(self):
        """Clear all telemetry data."""
        self._buffer = [None] * self._capacity
        self._index = 0
        self._size = 0
        self._dropped_points = 0
    
    def get_stats(self):
        """Get buffer statistics."""
        return {
            'capacity': self._capacity,
            'size': self._size,
            'utilization_pct': (self._size / self._capacity) * 100,
            'dropped_points': self._dropped_points
        }


class TelemetryCollector:
    """
    Main telemetry collection system for BAS controller.
    
    Design philosophy:
    - Collects data from controller status on each cycle
    - Non-blocking: minimal processing in main loop
    - Aggregation done on-demand when API is called
    - Extensible: supports custom collectors and metrics
    
    Extension points:
    - register_custom_collector(): Add custom data sources
    - Custom TelemetryPoint.custom_data: Add arbitrary metrics
    - Zone support: Set zone_id for multi-zone systems
    """
    
    def __init__(self, buffer_size=1000, csv_path=None, zone_id=None):
        self._buffer = TelemetryBuffer(buffer_size)
        self._logger = LoggerFactory.get_logger("Telemetry")
        self._csv_path = csv_path
        self._csv_enabled = csv_path is not None
        self._zone_id = zone_id  # Optional: for multi-zone deployments
        
        # Statistics
        self._collection_count = 0
        self._last_collection_ms = 0
        self._collection_interval_ms = 2000  # Match controller cycle
        
        # CSV state
        self._csv_write_count = 0
        self._csv_batch_size = 10  # Write every N points to reduce I/O
        self._csv_pending = []
        
        # Extensibility: custom metric collectors
        self._custom_collectors = []  # List of (name, callable) tuples
        
        # Initialize CSV file if enabled
        if self._csv_enabled:
            self._init_csv_file()
        
        self._logger.info("Telemetry collector initialized", 
                         buffer_size=buffer_size, 
                         csv_enabled=self._csv_enabled,
                         zone_id=zone_id)
    
    def _init_csv_file(self):
        """Initialize CSV file with headers."""
        try:
            # Check if file exists
            try:
                with open(self._csv_path, 'r'):
                    self._logger.info("CSV file exists, appending data")
                    return
            except OSError:
                pass
            
            # Create new file with headers
            with open(self._csv_path, 'w') as f:
                f.write("timestamp_ms,temp_tenths,setpoint_tenths,cool_active,heat_active,state,alarm,error_code\n")
            
            self._logger.info("Created new CSV file", path=self._csv_path)
            
        except Exception as e:
            self._logger.error("Failed to initialize CSV file", error=str(e))
            self._csv_enabled = False
    
    def register_custom_collector(self, name, collector_func):
        """
        Register a custom metric collector function.
        
        The collector function should return a dict of custom metrics:
        Example:
            def collect_humidity():
                return {'humidity_pct': read_humidity_sensor()}
            
            telemetry.register_custom_collector('humidity', collect_humidity)
        
        Args:
            name (str): Name of the custom collector
            collector_func (callable): Function that returns dict of metrics
        """
        self._custom_collectors.append((name, collector_func))
        self._logger.info("Registered custom collector", name=name)
    
    def collect(self, controller_status, custom_data=None):
        """
        Collect telemetry from controller status.
        
        Call this from main loop after controller.step().
        
        Args:
            controller_status: Controller status object
            custom_data (dict, optional): Additional custom metrics to include
        
        Returns:
            bool: True if point was collected, False if skipped
        
        Extension example:
            # Add custom sensor readings
            extra_data = {
                'humidity_pct': 65.5,
                'pressure_hpa': 1013.25,
                'aux_temp_c': 22.3
            }
            telemetry.collect(status, custom_data=extra_data)
        """
        if controller_status is None:
            return False
        
        try:
            current_time = time.ticks_ms()
            
            # Merge custom data from parameter and registered collectors
            merged_custom_data = {}
            if custom_data:
                merged_custom_data.update(custom_data)
            
            # Call registered custom collectors
            for collector_name, collector_func in self._custom_collectors:
                try:
                    collector_data = collector_func()
                    if collector_data:
                        merged_custom_data.update(collector_data)
                except Exception as e:
                    self._logger.warning("Custom collector failed", 
                                       name=collector_name, error=str(e))
            
            # Create telemetry point from controller status
            point = TelemetryPoint(
                timestamp_ms=current_time,
                temp_tenths=controller_status.temp_tenths,
                setpoint_tenths=controller_status.setpoint_tenths,
                cool_active=controller_status.cool_active,
                heat_active=controller_status.heat_active,
                state=controller_status.state,
                alarm=controller_status.alarm,
                error_code=controller_status.error_code,
                zone_id=self._zone_id,
                custom_data=merged_custom_data if merged_custom_data else None
            )
            
            # Add to buffer
            self._buffer.append(point)
            
            # CSV export if enabled
            if self._csv_enabled:
                self._csv_pending.append(point)
                if len(self._csv_pending) >= self._csv_batch_size:
                    self._flush_csv()
            
            self._collection_count += 1
            self._last_collection_ms = current_time
            
            # Periodic stats logging
            if self._collection_count % 300 == 0:  # Every ~10 minutes at 2s interval
                stats = self._buffer.get_stats()
                self._logger.info("Telemetry stats", 
                                collected=self._collection_count,
                                buffer_util_pct=stats['utilization_pct'])
            
            return True
            
        except Exception as e:
            self._logger.error("Telemetry collection failed", error=str(e))
            return False
    
    def _flush_csv(self):
        """Write pending points to CSV file."""
        if not self._csv_enabled or not self._csv_pending:
            return
        
        try:
            with open(self._csv_path, 'a') as f:
                for point in self._csv_pending:
                    line = f"{point.timestamp_ms},{point.temp_tenths},{point.setpoint_tenths},"
                    line += f"{1 if point.cool_active else 0},{1 if point.heat_active else 0},"
                    line += f"{point.state},{1 if point.alarm else 0},{point.error_code}\n"
                    f.write(line)
            
            self._csv_write_count += len(self._csv_pending)
            self._csv_pending.clear()
            
        except Exception as e:
            self._logger.error("CSV flush failed", error=str(e))
            # Don't disable CSV on single failure, but clear pending to prevent memory buildup
            self._csv_pending.clear()
    
    def force_csv_flush(self):
        """Force immediate CSV flush (call on shutdown)."""
        if self._csv_enabled:
            self._flush_csv()
    
    def get_recent_points(self, count=100, start_time_ms=None):
        """Get recent telemetry points for API."""
        return self._buffer.get_recent(count, start_time_ms)
    
    def get_time_series_data(self, duration_ms=600000, max_points=300):
        """
        Get time series data optimized for graphing.
        
        Args:
            duration_ms: Time window (default 10 minutes)
            max_points: Maximum points to return (for downsampling)
        
        Returns:
            Dictionary with arrays for efficient JSON transmission
        """
        start_time = time.ticks_ms() - duration_ms
        points = self._buffer.get_recent(count=None, start_time_ms=start_time)
        
        # Reverse to get chronological order (oldest first)
        points = list(reversed(points))
        
        # Downsample if needed
        if len(points) > max_points:
            step = len(points) // max_points
            points = points[::step]
        
        # Convert to array format for efficient transmission
        timestamps = []
        temperatures = []
        setpoints = []
        cooling = []
        heating = []
        states = []
        alarms = []
        
        for point in points:
            timestamps.append(point.timestamp_ms)
            # Convert temp_tenths to float for graphing (None becomes null in JSON)
            temperatures.append(point.temp_tenths / 10.0 if point.temp_tenths is not None else None)
            setpoints.append(point.setpoint_tenths / 10.0)
            cooling.append(1 if point.cool_active else 0)
            heating.append(1 if point.heat_active else 0)
            states.append(point.state)
            alarms.append(1 if point.alarm else 0)
        
        return {
            'timestamps': timestamps,
            'temperatures': temperatures,
            'setpoints': setpoints,
            'cooling': cooling,
            'heating': heating,
            'states': states,
            'alarms': alarms,
            'count': len(points),
            'duration_ms': duration_ms
        }

    def export_points(self,
                      duration_ms=600000,
                      limit=1000,
                      zone_filter=None,
                      since_ms=None,
                      fields=None,
                      compact=False):
        """
        Export telemetry as normalized points suitable for large-scale storage.
        Each point:
          - measurement: 'bas_controller'
          - tags: { zone_id?, state }
          - fields: { temperature_c, setpoint_c, cooling, heating, alarm, error_code }
          - timestamp_ms
        """
        now_ms = time.ticks_ms()
        start_time = (since_ms if since_ms is not None else (now_ms - duration_ms))
        src = self._buffer.get_recent(count=None, start_time_ms=start_time)
        # src is newest-first; iterate backwards to build up to `limit` without copying src
        exported = []
        remaining = limit
        # Normalize fields selection
        want = None
        if fields:
            # Expect comma-separated list
            want = {}
            for f in fields.split(','):
                want[f.strip()] = True
        for idx in range(len(src) - 1, -1, -1):  # oldest-first by appending reversed src
            if remaining == 0:
                break
            p = src[idx]
            # Normalize zone for comparison: None -> 'default'
            if zone_filter is not None and (p.zone_id if p.zone_id is not None else 'default') != zone_filter:
                continue
            # Build fields dict lazily and sparsely
            temp_c = (p.temp_tenths / 10.0) if p.temp_tenths is not None else None
            field_obj = {}
            def addf(name, value):
                if want is None or name in want:
                    field_obj[name] = value
            addf('temperature_c', temp_c)
            addf('setpoint_c', p.setpoint_tenths / 10.0)
            addf('cooling', 1 if p.cool_active else 0)
            addf('heating', 1 if p.heat_active else 0)
            addf('alarm', 1 if p.alarm else 0)
            addf('error_code', p.error_code)
            if compact:
                # Compact, flat form with short keys reduces payload and allocations
                exported.append({
                    'm': 'bas',
                    'tg': {
                        'z': p.zone_id if p.zone_id is not None else 'default',
                        's': p.state
                    },
                    'fd': field_obj,
                    'ts': p.timestamp_ms
                })
            else:
                exported.append({
                    'measurement': 'bas_controller',
                    'tags': {
                        'zone_id': p.zone_id if p.zone_id is not None else 'default',
                        'state': p.state,
                    },
                    'fields': field_obj,
                    'timestamp_ms': p.timestamp_ms
                })
            remaining -= 1
        return {
            'count': len(exported),
            'from_ms': start_time,
            'points': exported
        }
    
    def get_statistics(self, duration_ms=3600000):
        """
        Calculate aggregated statistics over time window.
        
        Args:
            duration_ms: Time window (default 1 hour)
        
        Returns:
            Dictionary with statistical summary
        """
        start_time = time.ticks_ms() - duration_ms
        points = self._buffer.get_recent(count=None, start_time_ms=start_time)
        
        if not points:
            return {'error': 'No data available'}
        
        # Calculate statistics
        valid_temps = [p.temp_tenths for p in points if p.temp_tenths is not None]
        
        if not valid_temps:
            temp_stats = {'error': 'No valid temperature readings'}
        else:
            temp_stats = {
                'min_c': min(valid_temps) / 10.0,
                'max_c': max(valid_temps) / 10.0,
                'avg_c': sum(valid_temps) / len(valid_temps) / 10.0,
                'current_c': points[0].temp_tenths / 10.0 if points[0].temp_tenths else None
            }
        
        # Count actuator cycles (state transitions)
        cooling_on_count = 0
        heating_on_count = 0
        for i in range(1, len(points)):
            if points[i].cool_active and not points[i-1].cool_active:
                cooling_on_count += 1
            if points[i].heat_active and not points[i-1].heat_active:
                heating_on_count += 1
        
        # Calculate duty cycles
        total_points = len(points)
        cooling_on_points = sum(1 for p in points if p.cool_active)
        heating_on_points = sum(1 for p in points if p.heat_active)
        
        duty_cycles = {
            'cooling_pct': (cooling_on_points / total_points) * 100 if total_points > 0 else 0,
            'heating_pct': (heating_on_points / total_points) * 100 if total_points > 0 else 0,
            'cooling_cycles': cooling_on_count,
            'heating_cycles': heating_on_count
        }
        
        # Alarm statistics
        alarm_points = sum(1 for p in points if p.alarm)
        alarm_pct = (alarm_points / total_points) * 100 if total_points > 0 else 0
        
        return {
            'duration_ms': duration_ms,
            'point_count': total_points,
            'temperature': temp_stats,
            'duty_cycles': duty_cycles,
            'alarm_pct': alarm_pct,
            'current_state': points[0].state if points else None,
            'current_setpoint_c': points[0].setpoint_tenths / 10.0 if points else None
        }
    
    def get_system_health(self):
        """Get telemetry system health metrics."""
        buffer_stats = self._buffer.get_stats()
        
        # Calculate collection rate
        uptime_ms = time.ticks_ms()
        collection_rate = self._collection_count / (uptime_ms / 1000.0) if uptime_ms > 0 else 0
        
        health = {
            'enabled': True,
            'collection_count': self._collection_count,
            'collection_rate_hz': collection_rate,
            'buffer_stats': buffer_stats,
            'csv_enabled': self._csv_enabled,
            'csv_write_count': self._csv_write_count if self._csv_enabled else None,
            'csv_pending': len(self._csv_pending) if self._csv_enabled else None
        }
        
        return health
    
    def clear(self):
        """Clear all telemetry data (for testing/maintenance)."""
        self._buffer.clear()
        self._csv_pending.clear()
        self._collection_count = 0
        self._logger.info("Telemetry data cleared")
    
    def shutdown(self):
        """Graceful shutdown - flush pending CSV data."""
        if self._csv_enabled:
            self._flush_csv()
            self._logger.info("Telemetry shutdown complete", 
                            total_points=self._collection_count,
                            csv_writes=self._csv_write_count)

