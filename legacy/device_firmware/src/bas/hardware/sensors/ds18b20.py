# core/ds18b20.py

import time
from machine import Pin
import onewire, ds18x20

# Try to import interfaces (v2), but don't require them (v1 compatibility)
try:
    from bas.hardware.interfaces import TemperatureSensor, SensorReading
    _has_interfaces = True
except ImportError:
    _has_interfaces = False
    TemperatureSensor = object
    SensorReading = None

# Legacy class for backward compatibility
class TempReading:
    __slots__ = ("millis", "ok", "c_tenths")
    
    def __init__(self, millis: int, ok: bool, c_tenths: int):
        self.millis = millis
        self.ok = ok
        self.c_tenths = c_tenths  # temperature in tenths of °C

# Error codes for sensor faults
class DS18B20ErrorCodes:
    NO_ERROR = 0
    SENSOR_NOT_FOUND = 1
    CONVERSION_FAILED = 2
    READ_FAILED = 3
    INVALID_TEMPERATURE = 4
        
class DS18B20Sensor(TemperatureSensor):
    def __init__(self, pin_num: int, max_retries: int = 3, convert_wait_ms: int = 750):
        self._ow = onewire.OneWire(Pin(pin_num))
        self._ds = ds18x20.DS18X20(self._ow)
        
        roms = self._ds.scan()
        
        if not roms:
            raise RuntimeError("DS18B20 not found on bus")
        
        # Use the first sensor found
        self._rom = roms[0]
        self._max_retries = max_retries
        self._convert_wait_ms = convert_wait_ms
        
        # Initialize readings
        self._legacy_reading = TempReading(time.ticks_ms(), False, 0)
        if _has_interfaces:
            self._last_reading = SensorReading(time.ticks_ms(), False, 0, DS18B20ErrorCodes.SENSOR_NOT_FOUND)
        else:
            self._last_reading = self._legacy_reading
        
    def read(self):
        """Read temperature. Returns SensorReading (v2) or TempReading (v1)."""
        timestamp = time.ticks_ms()
        
        # attempt conversion + read with retries
        for retry in range(self._max_retries):
            try:
                self._ds.convert_temp()
                time.sleep_ms(self._convert_wait_ms)
                
                c = self._ds.read_temp(self._rom)
                if c is None:
                    continue
                
                # Convert to tenths of °C avoiding float drift
                c_tenths = int(round(c * 10))
                
                # Sanity check temperature range (-55°C to +125°C for DS18B20)
                if c_tenths < -550 or c_tenths > 1250:
                    self._legacy_reading = TempReading(timestamp, False, 0)
                    if _has_interfaces:
                        self._last_reading = SensorReading(timestamp, False, 0, DS18B20ErrorCodes.INVALID_TEMPERATURE)
                    else:
                        self._last_reading = self._legacy_reading
                    continue
                
                # Store readings - legacy first, then v2
                self._legacy_reading = TempReading(timestamp, True, c_tenths)
                if _has_interfaces:
                    self._last_reading = SensorReading(timestamp, True, c_tenths, DS18B20ErrorCodes.NO_ERROR)
                else:
                    self._last_reading = self._legacy_reading
                
                # Always return legacy TempReading for v1 compatibility
                return self._legacy_reading
                
            except Exception as e:
                # brief backoff then retry
                time.sleep_ms(50)
                
        # On failure: return error reading
        self._legacy_reading = TempReading(timestamp, False, 0)
        if _has_interfaces:
            self._last_reading = SensorReading(timestamp, False, 0, DS18B20ErrorCodes.READ_FAILED)
        else:
            self._last_reading = self._legacy_reading
        
        # Always return legacy TempReading for v1 compatibility
        return self._legacy_reading
    
    def last_reading(self):
        """Return last reading (v2 interface)."""
        return self._last_reading if _has_interfaces else self._legacy_reading
    
    def reset(self):
        """Reset sensor state (v2 interface)."""
        timestamp = time.ticks_ms()
        if _has_interfaces:
            self._last_reading = SensorReading(timestamp, False, 0, DS18B20ErrorCodes.NO_ERROR)
        self._legacy_reading = TempReading(timestamp, False, 0)
    
    def close(self):
        """Clean up resources (v2 interface)."""
        # DS18B20 doesn't need explicit cleanup
        pass
    
    # Legacy method for v1 backward compatibility
    def last(self):
        return self._legacy_reading
    
    