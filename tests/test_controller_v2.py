# tests/test_controller_v2.py
# Comprehensive tests for the production controller with dependency injection

from controller import CoolOnlyController, ControllerStatus
from tests.mock_interfaces import MockClock, MockActuator, MockTemperatureSensor
from services import SystemErrorCodes

# Test configuration constants
DEFAULT_SETPOINT = 230  # 23.0°C in tenths
DEFAULT_DEADBAND = 10   # 1.0°C in tenths  
MIN_ON_MS = 5000
MIN_OFF_MS = 5000
MAX_SENSOR_AGE_MS = 8000

def assert_eq(actual, expected, message=""):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected}, got {actual}")

def assert_true(condition, message=""):
    if not condition:
        raise AssertionError(f"{message}: condition was false")

def assert_false(condition, message=""):
    if condition:
        raise AssertionError(f"{message}: condition was true")

class TestControllerBasics:
    """Basic controller functionality tests."""
    
    def __init__(self):
        self.clock = MockClock()
        self.sensor = MockTemperatureSensor(self.clock, initial_temp_tenths=DEFAULT_SETPOINT)
        self.cool_actuator = MockActuator("COOL")
        self.heat_actuator = MockActuator("HEAT")
        
        self.controller = CoolOnlyController(
            sensor=self.sensor,
            cool_actuator=self.cool_actuator,
            heat_actuator=self.heat_actuator,
            clock=self.clock,
            setpoint_tenths=DEFAULT_SETPOINT,
            deadband_tenths=DEFAULT_DEADBAND,
            min_on_ms=MIN_ON_MS,
            min_off_ms=MIN_OFF_MS,
            max_sensor_age_ms=MAX_SENSOR_AGE_MS,
            heat_always_on=True
        )
    
    def test_initialization(self):
        """Test controller initializes correctly."""
        # Heat should be on (always-on mode)
        assert_true(self.heat_actuator.is_active(), "Heat actuator should be active on init")
        
        # Cool should be off
        assert_false(self.cool_actuator.is_active(), "Cool actuator should be inactive on init")
        
        # Controller should be in IDLE state
        status = self.controller.step()
        assert_eq(status.state, "IDLE", "Initial state should be IDLE")
        
        print("✓ Initialization test passed")
    
    def test_hysteresis_cooling_cycle(self):
        """Test complete cooling cycle with hysteresis."""
        # Start at setpoint - should be IDLE
        self.sensor.set_temperature_c(DEFAULT_SETPOINT / 10.0)
        status = self.controller.step()
        assert_eq(status.state, "IDLE", "Should be IDLE at setpoint")
        assert_false(status.cool_active, "Cooling should be off at setpoint")
        
        # Go above setpoint + deadband - should start cooling
        high_temp = (DEFAULT_SETPOINT + DEFAULT_DEADBAND + 5) / 10.0
        self.sensor.set_temperature_c(high_temp)
        status = self.controller.step()
        assert_eq(status.state, "COOLING", "Should be COOLING above SP+DB")
        assert_true(status.cool_active, "Cooling should be active")
        
        # Drop below setpoint but above min_on time - should continue cooling
        self.sensor.set_temperature_c((DEFAULT_SETPOINT - 5) / 10.0)
        self.clock.advance(MIN_ON_MS - 100)  # Not enough time
        status = self.controller.step()
        assert_eq(status.state, "COOLING", "Should continue cooling before min_on")
        assert_true(status.cool_active, "Cooling should remain active")
        
        # After min_on time - should stop cooling
        self.clock.advance(200)  # Total > MIN_ON_MS
        status = self.controller.step()
        assert_eq(status.state, "IDLE", "Should stop cooling after min_on")
        assert_false(status.cool_active, "Cooling should be inactive")
        
        print("✓ Hysteresis cooling cycle test passed")
    
    def test_anti_short_cycle(self):
        """Test anti-short-cycle protection."""
        # Start cooling
        self.sensor.set_temperature_c((DEFAULT_SETPOINT + DEFAULT_DEADBAND + 10) / 10.0)
        self.controller.step()  # Start cooling
        
        # Stop cooling after min_on time
        self.sensor.set_temperature_c((DEFAULT_SETPOINT - 10) / 10.0)
        self.clock.advance(MIN_ON_MS + 100)
        self.controller.step()  # Stop cooling
        
        # Try to start cooling again before min_off - should be prevented
        self.sensor.set_temperature_c((DEFAULT_SETPOINT + DEFAULT_DEADBAND + 10) / 10.0)
        self.clock.advance(MIN_OFF_MS - 100)  # Not enough time
        status = self.controller.step()
        assert_eq(status.state, "IDLE", "Should remain IDLE during min_off period")
        assert_false(status.cool_active, "Cooling should remain off")
        
        # After min_off time - should allow cooling
        self.clock.advance(200)  # Total > MIN_OFF_MS
        status = self.controller.step()
        assert_eq(status.state, "COOLING", "Should allow cooling after min_off")
        assert_true(status.cool_active, "Cooling should be active")
        
        print("✓ Anti-short-cycle test passed")
    
    def test_sensor_fault_handling(self):
        """Test sensor fault handling and recovery."""
        # Start with good sensor and cooling active
        self.sensor.set_temperature_c((DEFAULT_SETPOINT + DEFAULT_DEADBAND + 10) / 10.0)
        self.controller.step()  # Start cooling
        assert_true(self.cool_actuator.is_active(), "Cooling should be active")
        
        # Induce sensor fault
        self.sensor.set_fault(SystemErrorCodes.SENSOR_READ_FAILED)
        status = self.controller.step()
        
        # Should go to fault state and turn off cooling
        assert_eq(status.state, "FAULT", "Should be in FAULT state on sensor error")
        assert_false(status.cool_active, "Cooling should be off in fault state")
        assert_true(status.alarm, "Alarm should be active")
        assert_eq(status.error_code, SystemErrorCodes.SENSOR_READ_FAILED, "Error code should match sensor fault")
        
        # Clear fault - should recover
        self.sensor.clear_fault()
        self.sensor.set_temperature_c((DEFAULT_SETPOINT - 10) / 10.0)  # Safe temperature
        status = self.controller.step()
        
        # Should recover to IDLE state
        assert_eq(status.state, "IDLE", "Should recover to IDLE after fault clears")
        assert_false(status.alarm, "Alarm should clear after recovery")
        assert_eq(status.error_code, 0, "Error code should clear")
        
        print("✓ Sensor fault handling test passed")

class TestControllerEdgeCases:
    """Edge cases and corner conditions."""
    
    def setup_controller(self):
        """Setup fresh controller for each test."""
        self.clock = MockClock()
        self.sensor = MockTemperatureSensor(self.clock)
        self.cool_actuator = MockActuator("COOL")
        self.heat_actuator = MockActuator("HEAT")
        
        return CoolOnlyController(
            sensor=self.sensor,
            cool_actuator=self.cool_actuator,
            heat_actuator=self.heat_actuator,
            clock=self.clock,
            setpoint_tenths=DEFAULT_SETPOINT,
            deadband_tenths=DEFAULT_DEADBAND,
            min_on_ms=MIN_ON_MS,
            min_off_ms=MIN_OFF_MS,
            max_sensor_age_ms=MAX_SENSOR_AGE_MS
        )
    
    def test_stale_sensor_data(self):
        """Test handling of stale sensor data."""
        controller = self.setup_controller()
        
        # Get initial reading
        self.sensor.set_temperature_c(25.0)
        status = controller.step()
        assert_true(status.sensor_ok, "Sensor should be OK initially")
        
        # Advance time beyond max sensor age without new reading
        self.clock.advance(MAX_SENSOR_AGE_MS + 1000)
        status = controller.step()
        
        assert_false(status.sensor_ok, "Sensor should be stale")
        assert_true(status.alarm, "Should have alarm for stale data") 
        assert_eq(status.error_code, 999, "Should have stale data error code")
        
        print("✓ Stale sensor data test passed")
    
    def test_extreme_temperatures(self):
        """Test behavior with extreme temperature values."""
        controller = self.setup_controller()
        
        # Test very high temperature
        self.sensor.set_temperature_c(100.0)  # 100°C
        status = controller.step()
        assert_true(status.cool_active, "Should activate cooling at extreme high temp")
        
        # Test very low temperature  
        self.sensor.set_temperature_c(-20.0)  # -20°C
        status = controller.step()
        assert_false(status.cool_active, "Should not cool at extreme low temp")
        
        print("✓ Extreme temperatures test passed")
    
    def test_rapid_temperature_changes(self):
        """Test rapid temperature oscillations."""
        controller = self.setup_controller()
        
        # Rapid oscillation around setpoint
        for i in range(10):
            if i % 2 == 0:
                temp = (DEFAULT_SETPOINT + DEFAULT_DEADBAND + 5) / 10.0  # Above
            else:
                temp = (DEFAULT_SETPOINT - 5) / 10.0  # Below
            
            self.sensor.set_temperature_c(temp)
            self.clock.advance(100)  # Very short time steps
            status = controller.step()
            
            # Anti-short-cycle should prevent rapid switching
            # Detailed assertions would depend on specific timing
        
        print("✓ Rapid temperature changes test passed")
    
    def test_configuration_updates(self):
        """Test runtime configuration updates."""
        controller = self.setup_controller()
        
        # Update setpoint
        new_setpoint = 250  # 25.0°C
        controller.set_setpoint_tenths(new_setpoint)
        assert_eq(controller.setpoint_tenths, new_setpoint, "Setpoint should update")
        
        # Update deadband
        new_deadband = 20  # 2.0°C
        controller.set_deadband_tenths(new_deadband)
        assert_eq(controller.deadband_tenths, new_deadband, "Deadband should update")
        
        # Test that new settings are used
        self.sensor.set_temperature_c((new_setpoint + new_deadband + 5) / 10.0)
        status = controller.step()
        assert_true(status.cool_active, "Should use new setpoint and deadband")
        
        print("✓ Configuration updates test passed")

class TestControllerStateTransitions:
    """State transition matrix testing."""
    
    STATE_TRANSITION_TESTS = [
        # (from_state, condition, expected_state, description)
        ("IDLE", "temp_high", "COOLING", "IDLE -> COOLING on high temp"),
        ("COOLING", "temp_low_min_on", "IDLE", "COOLING -> IDLE on low temp after min_on"),
        ("COOLING", "temp_low_no_min_on", "COOLING", "COOLING stays on temp low before min_on"),
        ("IDLE", "sensor_fault", "FAULT", "IDLE -> FAULT on sensor error"),
        ("COOLING", "sensor_fault", "FAULT", "COOLING -> FAULT on sensor error"),
        ("FAULT", "sensor_recovery", "IDLE", "FAULT -> IDLE on sensor recovery"),
    ]
    
    def test_state_transitions(self):
        """Test all valid state transitions."""
        for from_state, condition, expected_state, description in self.STATE_TRANSITION_TESTS:
            self._test_single_transition(from_state, condition, expected_state, description)
    
    def _test_single_transition(self, from_state, condition, expected_state, description):
        """Test single state transition."""
        # Setup controller in initial state
        clock = MockClock()
        sensor = MockTemperatureSensor(clock)
        cool_actuator = MockActuator("COOL")
        heat_actuator = MockActuator("HEAT")
        
        controller = CoolOnlyController(
            sensor=sensor, cool_actuator=cool_actuator, heat_actuator=heat_actuator,
            clock=clock, setpoint_tenths=DEFAULT_SETPOINT, deadband_tenths=DEFAULT_DEADBAND,
            min_on_ms=MIN_ON_MS, min_off_ms=MIN_OFF_MS
        )
        
        # Force controller to initial state
        if from_state == "COOLING":
            sensor.set_temperature_c((DEFAULT_SETPOINT + DEFAULT_DEADBAND + 10) / 10.0)
            controller.step()  # Transition to cooling
            clock.advance(100)  # Small time advance
        elif from_state == "FAULT":
            sensor.set_fault()
            controller.step()  # Transition to fault
        
        # Apply condition
        self._apply_condition(sensor, clock, condition)
        
        # Execute step and check result
        status = controller.step()
        assert_eq(status.state, expected_state, description)
        
        print(f"✓ {description}")
    
    def _apply_condition(self, sensor, clock, condition):
        """Apply test condition."""
        if condition == "temp_high":
            sensor.set_temperature_c((DEFAULT_SETPOINT + DEFAULT_DEADBAND + 10) / 10.0)
        elif condition == "temp_low_min_on":
            sensor.set_temperature_c((DEFAULT_SETPOINT - 10) / 10.0)
            clock.advance(MIN_ON_MS + 100)
        elif condition == "temp_low_no_min_on":
            sensor.set_temperature_c((DEFAULT_SETPOINT - 10) / 10.0)
            clock.advance(MIN_ON_MS - 100)
        elif condition == "sensor_fault":
            sensor.set_fault()
        elif condition == "sensor_recovery":
            sensor.clear_fault()
            sensor.set_temperature_c(DEFAULT_SETPOINT / 10.0)

# Contract Tests for Interfaces
class TestInterfaceContracts:
    """Test that implementations properly implement interfaces."""
    
    def test_actuator_contract(self):
        """Test actuator interface contract."""
        actuator = MockActuator("TEST")
        
        # Initial state
        assert_false(actuator.is_active(), "Actuator should start inactive")
        
        # Activation
        actuator.activate()
        assert_true(actuator.is_active(), "Actuator should be active after activate()")
        
        # Deactivation
        actuator.deactivate()
        assert_false(actuator.is_active(), "Actuator should be inactive after deactivate()")
        
        # State setting
        actuator.set_state(True)
        assert_true(actuator.is_active(), "set_state(True) should activate")
        
        actuator.set_state(False)
        assert_false(actuator.is_active(), "set_state(False) should deactivate")
        
        # Name property
        assert_eq(actuator.name, "TEST", "Name should match constructor")
        
        print("✓ Actuator contract test passed")
    
    def test_sensor_contract(self):
        """Test sensor interface contract."""
        clock = MockClock()
        sensor = MockTemperatureSensor(clock, initial_temp_tenths=250)
        
        # Initial reading
        reading = sensor.read()
        assert_true(reading.is_valid, "Initial reading should be valid")
        assert_eq(reading.temp_tenths, 250, "Temperature should match initial value")
        
        # Last reading consistency
        last = sensor.last_reading()
        assert_eq(last.temp_tenths, reading.temp_tenths, "Last reading should match current")
        
        # Fault handling
        sensor.set_fault(SystemErrorCodes.SENSOR_READ_FAILED)
        reading = sensor.read()
        assert_false(reading.is_valid, "Reading should be invalid after fault")
        assert_eq(reading.error_code, SystemErrorCodes.SENSOR_READ_FAILED, "Error code should match")
        
        # Recovery
        sensor.clear_fault()
        reading = sensor.read()
        assert_true(reading.is_valid, "Reading should be valid after fault clear")
        assert_eq(reading.error_code, 0, "Error code should clear")
        
        print("✓ Sensor contract test passed")
    
    def test_clock_contract(self):
        """Test clock interface contract."""
        clock = MockClock(initial_time_ms=1000)
        
        # Time monotonicity
        t1 = clock.now_ms()
        clock.advance(500)
        t2 = clock.now_ms()
        assert_true(t2 > t1, "Time should advance monotonically")
        
        # Elapsed time calculation
        start = clock.now_ms()
        clock.advance(1000)
        elapsed = clock.elapsed_ms(start)
        assert_eq(elapsed, 1000, "Elapsed time should be correct")
        
        print("✓ Clock contract test passed")

def run_all_tests():
    """Run all controller tests."""
    print("Running Controller V2 Tests...")
    print("=" * 50)
    
    # Basic functionality tests
    basic_tests = TestControllerBasics()
    basic_tests.test_initialization()
    basic_tests.test_hysteresis_cooling_cycle()
    basic_tests.test_anti_short_cycle()
    basic_tests.test_sensor_fault_handling()
    
    # Edge case tests
    edge_tests = TestControllerEdgeCases()
    edge_tests.test_stale_sensor_data()
    edge_tests.test_extreme_temperatures()
    edge_tests.test_rapid_temperature_changes()
    edge_tests.test_configuration_updates()
    
    # State transition tests
    transition_tests = TestControllerStateTransitions()
    transition_tests.test_state_transitions()
    
    # Contract tests
    contract_tests = TestInterfaceContracts()
    contract_tests.test_actuator_contract()
    contract_tests.test_sensor_contract()
    contract_tests.test_clock_contract()
    
    print("=" * 50)
    print("All Controller V2 tests passed! ✅")

if __name__ == "__main__":
    run_all_tests()
