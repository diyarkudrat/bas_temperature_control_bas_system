# controller.py
# Production-grade cool-only controller with dependency injection and error handling

from interfaces import TemperatureSensor, Actuator, Clock, SensorReading

class ControllerStatus:
    """
    Immutable snapshot of controller state after each step().
    All temperatures are tenths of °C (ints).
    """
    __slots__ = ('state', 'temp_tenths', 'setpoint_tenths', 'deadband_tenths',
                 'cool_active', 'heat_active', 'alarm', 'sensor_ok', 'error_code', 'age_ms')
    
    def __init__(self, state="IDLE", temp_tenths=None, setpoint_tenths=230, 
                 deadband_tenths=10, cool_active=False, heat_active=False,
                 alarm=False, sensor_ok=False, error_code=0, age_ms=0):
        self.state = state
        self.temp_tenths = temp_tenths
        self.setpoint_tenths = setpoint_tenths
        self.deadband_tenths = deadband_tenths
        self.cool_active = cool_active
        self.heat_active = heat_active
        self.alarm = alarm
        self.sensor_ok = sensor_ok
        self.error_code = error_code
        self.age_ms = age_ms

class CoolOnlyController:
    """
    Cool-only closed-loop controller with hysteresis and anti-short-cycle.
    Uses dependency injection for hardware abstraction.
    
    - Cool actuator turns ON when T > SP + DB (and min OFF elapsed)
    - Cool actuator turns OFF when T <= SP (and min ON elapsed)  
    - Sensor fault => actuators safe state + alarm
    - Heat actuator can be always-on or controlled
    """
    
    def __init__(
        self,
        sensor: TemperatureSensor,
        cool_actuator: Actuator,
        heat_actuator: Actuator,
        clock: Clock,
        setpoint_tenths: int,
        deadband_tenths: int,
        min_on_ms: int = 10000,
        min_off_ms: int = 10000,
        max_sensor_age_ms: int = 8000,
        heat_always_on: bool = True
    ):
        # Dependencies (injected)
        self._sensor = sensor
        self._cool = cool_actuator
        self._heat = heat_actuator
        self._clock = clock
        
        # Configuration
        self._setpoint = int(setpoint_tenths)
        self._deadband = max(0, int(deadband_tenths))
        self._min_on_ms = min_on_ms
        self._min_off_ms = min_off_ms
        self._max_sensor_age_ms = max_sensor_age_ms
        self._heat_always_on = heat_always_on
        
        # State
        self._state = "IDLE"
        self._last_on_ms = None  # when fan last turned ON
        self._last_off_ms = self._clock.now_ms() - self._min_off_ms  # min-off satisfied at startup
        self._last_status = None
        
        # Initialize heat actuator policy
        if self._heat_always_on:
            self._heat.activate()
        else:
            self._heat.deactivate()
    
    # ---------- Pure decision helpers ----------
    
    def _should_turn_on(self, temp_tenths) -> bool:
        """Check if cooling should turn on based on temperature."""
        if temp_tenths is None:
            return False
        return temp_tenths > (self._setpoint + self._deadband)
    
    def _should_turn_off(self, temp_tenths) -> bool:
        """Check if cooling should turn off based on temperature."""
        if temp_tenths is None:
            return True  # Fail-safe: turn off on sensor fault
        return temp_tenths <= self._setpoint
    
    def _min_on_elapsed(self) -> bool:
        """Check if minimum ON time has elapsed."""
        if self._last_on_ms is None:
            return True
        return self._clock.elapsed_ms(self._last_on_ms) >= self._min_on_ms
    
    def _min_off_elapsed(self) -> bool:
        """Check if minimum OFF time has elapsed."""
        return self._clock.elapsed_ms(self._last_off_ms) >= self._min_off_ms
    
    # ---------- Public API ----------
    
    def set_setpoint_tenths(self, sp_tenths: int) -> None:
        """Update setpoint in tenths of °C."""
        self._setpoint = int(sp_tenths)

    def set_deadband_tenths(self, db_tenths: int) -> None:  
        """Update deadband in tenths of °C."""
        self._deadband = max(0, int(db_tenths))
    
    @property
    def setpoint_tenths(self) -> int:
        return self._setpoint
    
    @property  
    def deadband_tenths(self) -> int:
        return self._deadband
        
    def step(self) -> ControllerStatus:
        """
        Execute one control cycle:
          - read sensor
          - update actuators according to hysteresis & anti-short-cycle
          - apply fail-safe on faults
        Return a status snapshot.
        """
        
        current_time = self._clock.now_ms()
        
        # Read sensor
        reading = self._sensor.read()
        
        # Handle both TempReading (v1) and SensorReading (v2) formats
        if hasattr(reading, 'is_valid'):
            # V2 format (SensorReading)
            sensor_ok = reading.is_valid and not reading.is_stale(current_time, self._max_sensor_age_ms)
            temp_tenths = reading.temp_tenths if sensor_ok else None
            error_code = reading.error_code if not sensor_ok else 0
        else:
            # V1 format (TempReading)
            sensor_ok = reading.ok
            temp_tenths = reading.c_tenths if reading.ok else None
            error_code = 0 if reading.ok else 102  # SENSOR_READ_FAILED
        
        if not sensor_ok:
            # Fail-safe: force safe state and raise alarm
            self._transition_to_fault()
            alarm = True
            # error_code already set above based on reading type
        else:
            # Normal operation based on FSM
            alarm = False
            error_code = 0
            
            if self._state == "IDLE":
                if self._should_turn_on(temp_tenths) and self._min_off_elapsed():
                    self._transition_cooling_on()
            elif self._state == "COOLING":
                if self._should_turn_off(temp_tenths) and self._min_on_elapsed():
                    self._transition_cooling_off()
            elif self._state == "FAULT":
                # Try to recover from fault if sensor is now good
                self._transition_cooling_off()  # Go to IDLE
            else:
                # Unknown state: fail safe
                self._transition_to_fault()
                alarm = True
                error_code = 500  # Unknown state error
        
        # Create status snapshot
        status = ControllerStatus(
            state=self._state,
            temp_tenths=temp_tenths,
            setpoint_tenths=self._setpoint,
            deadband_tenths=self._deadband,
            cool_active=self._cool.is_active(),
            heat_active=self._heat.is_active(),
            alarm=alarm,
            sensor_ok=sensor_ok,
            error_code=error_code,
            age_ms=reading.age_ms(current_time) if hasattr(reading, 'age_ms') else 0
        )
        
        self._last_status = status
        return status
    
    # ---------- State transitions ----------
    
    def _transition_cooling_on(self) -> None:
        """Transition to COOLING state."""
        self._cool.activate()
        self._state = "COOLING"
        self._last_on_ms = self._clock.now_ms()

    def _transition_cooling_off(self) -> None:
        """Transition to IDLE state."""
        self._cool.deactivate()
        self._state = "IDLE"
        self._last_off_ms = self._clock.now_ms()

    def _transition_to_fault(self) -> None:
        """Transition to FAULT state with safe actuator states."""
        self._cool.deactivate()  # Fail-safe: turn off cooling
        if not self._heat_always_on:
            self._heat.deactivate()  # Turn off heat if not always-on
        self._state = "FAULT"
        self._last_off_ms = self._clock.now_ms()
    
    def force_safe_state(self) -> None:
        """Force all actuators to safe state (for emergency shutdown)."""
        self._transition_to_fault()
    
    @property
    def last_status(self):
        """Return last status for external access (API, etc.)."""
        return self._last_status
    
    def close(self) -> None:
        """Clean up resources."""
        self._sensor.close()
        self._cool.close()
        self._heat.close()
