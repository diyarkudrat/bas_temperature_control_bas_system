# interfaces/sensor.py
# Abstract temperature sensor interface

class SensorReading:
    """Immutable sensor reading with timestamp and validity."""
    __slots__ = ("timestamp_ms", "is_valid", "temp_tenths", "error_code")
    
    def __init__(self, timestamp_ms: int, is_valid: bool, temp_tenths: int, error_code: int = 0):
        self.timestamp_ms = timestamp_ms
        self.is_valid = is_valid
        self.temp_tenths = temp_tenths  # Temperature in tenths of °C
        self.error_code = error_code    # 0 = no error, >0 = fault codes
    
    def age_ms(self, current_ms: int) -> int:
        """Return age of reading in milliseconds."""
        return current_ms - self.timestamp_ms
    
    def is_stale(self, current_ms: int, max_age_ms: int) -> bool:
        """Check if reading is stale."""
        return self.age_ms(current_ms) > max_age_ms

class TemperatureSensor:
    """Abstract interface for temperature sensors."""
    
    def read(self) -> SensorReading:
        """Read current temperature. Must be non-blocking."""
        raise NotImplementedError
    
    def last_reading(self) -> SensorReading:
        """Return last successful reading, may be stale."""
        raise NotImplementedError
    
    def reset(self) -> None:
        """Reset sensor state, clear errors."""
        raise NotImplementedError
    
    def close(self) -> None:
        """Clean up resources."""
        pass
