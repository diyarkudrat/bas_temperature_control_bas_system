# tests/mock_interfaces.py
# Mock implementations of interfaces for testing

from interfaces import TemperatureSensor, SensorReading, Actuator, Clock

class MockClock(Clock):
    """Mock clock for deterministic testing."""
    
    def __init__(self, initial_time_ms: int = 0):
        self._time_ms = initial_time_ms
    
    def now_ms(self) -> int:
        return self._time_ms
    
    def advance(self, ms: int) -> None:
        """Advance time by specified milliseconds."""
        self._time_ms += ms
    
    def sleep_ms(self, ms: int) -> None:
        # In tests, we don't actually sleep
        self.advance(ms)

class MockActuator(Actuator):
    """Mock actuator for testing."""
    
    def __init__(self, name: str = "MOCK"):
        self._name = name
        self._active = False
        self.activation_count = 0
        self.deactivation_count = 0
    
    def activate(self) -> None:
        self._active = True
        self.activation_count += 1
    
    def deactivate(self) -> None:
        self._active = False
        self.deactivation_count += 1
    
    def is_active(self) -> bool:
        return self._active
    
    @property
    def name(self) -> str:
        return self._name
    
    def reset_counters(self) -> None:
        """Reset activation counters for test isolation."""
        self.activation_count = 0
        self.deactivation_count = 0

class MockTemperatureSensor(TemperatureSensor):
    """Mock temperature sensor for testing."""
    
    def __init__(self, clock: MockClock, initial_temp_tenths: int = 230, initial_ok: bool = True):
        self._clock = clock
        self._temp_tenths = initial_temp_tenths
        self._is_valid = initial_ok
        self._error_code = 0
        self._last_reading = SensorReading(
            timestamp_ms=clock.now_ms(),
            is_valid=initial_ok,
            temp_tenths=initial_temp_tenths,
            error_code=0
        )
    
    def read(self) -> SensorReading:
        """Return current sensor reading."""
        self._last_reading = SensorReading(
            timestamp_ms=self._clock.now_ms(),
            is_valid=self._is_valid,
            temp_tenths=self._temp_tenths if self._is_valid else 0,
            error_code=self._error_code
        )
        return self._last_reading
    
    def last_reading(self) -> SensorReading:
        return self._last_reading
    
    def reset(self) -> None:
        self._is_valid = True
        self._error_code = 0
        self._last_reading = SensorReading(
            timestamp_ms=self._clock.now_ms(),
            is_valid=True,
            temp_tenths=self._temp_tenths,
            error_code=0
        )
    
    # Test control methods
    def set_temperature_c(self, temp_c: float) -> None:
        """Set temperature in Celsius."""
        self._temp_tenths = int(round(temp_c * 10))
    
    def set_fault(self, error_code: int = 1) -> None:
        """Simulate sensor fault."""
        self._is_valid = False
        self._error_code = error_code
    
    def clear_fault(self) -> None:
        """Clear sensor fault."""
        self._is_valid = True
        self._error_code = 0
