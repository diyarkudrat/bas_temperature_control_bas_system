# tests/test_controller.py
# Run on Pico REPL:
# >>> import tests.test_controller as t; t.run_all()

from controller import CoolOnlyController
from config.config import DEFAULT_SETPOINT_C, DEADBAND_TENTHS_C, MIN_ON_MS, MIN_OFF_MS
import controller as controller_module

from tests.mock_core_objects import FakeClock, MockRelay, MockSensor

def _inject_clock(fake: FakeClock):
    # Monkeypatch the controller's bound clock functions
    controller_module.now_ms = fake.now_ms
    controller_module.elapsed_ms = fake.elapsed_ms

def assert_eq(a, b, msg):
    if a != b:
        raise AssertionError(f"{msg}: expected {b}, got {a}")

def test_hysteresis_turn_on_off():
    clk = FakeClock(); _inject_clock(clk)
    sensor = MockSensor(initial_tenths=DEFAULT_SETPOINT_C)  # at SP
    cool = MockRelay("COOL")
    heat = MockRelay("HEAT")

    ctrl = CoolOnlyController(sensor, cool, heat,
                              setpoint_tenths=DEFAULT_SETPOINT_C,
                              deadband_tenths=DEADBAND_TENTHS_C)

    # At setpoint: fan should be OFF (IDLE)
    s = ctrl.step()
    assert_eq(cool.is_on(), False, "fan initially off")
    assert_eq(s.state, "IDLE", "state initially IDLE")

    # Go just above SP + DB -> should turn ON (respecting min OFF, which has elapsed since init)
    high_c = (DEFAULT_SETPOINT_C + DEADBAND_TENTHS_C + 1) / 10.0
    sensor.set_temp_c(high_c)
    s = ctrl.step()
    assert_eq(cool.is_on(), True, "fan turned on above SP+DB")
    assert_eq(s.state, "COOLING", "state COOLING")

    # Now drop to <= SP -> must turn OFF but only after MIN_ON elapsed
    sensor.set_temp_c(DEFAULT_SETPOINT_C / 10.0)
    # Not enough time yet:
    clk.advance(MIN_ON_MS - 100)
    s = ctrl.step()
    assert_eq(cool.is_on(), True, "fan held on until min-on elapsed")

    # After min-on:
    clk.advance(200)
    s = ctrl.step()
    assert_eq(cool.is_on(), False, "fan off after min-on elapsed")
    assert_eq(s.state, "IDLE", "state back to IDLE")

def test_min_off_prevents_chatter():
    clk = FakeClock(); _inject_clock(clk)
    sensor = MockSensor(initial_tenths=DEFAULT_SETPOINT_C)
    cool = MockRelay("COOL"); heat = MockRelay("HEAT")
    ctrl = CoolOnlyController(sensor, cool, heat)

    # Trigger ON
    sensor.set_temp_c((DEFAULT_SETPOINT_C + DEADBAND_TENTHS_C + 2)/10.0)
    ctrl.step()
    assert_eq(cool.is_on(), True, "fan on")

    # Turn OFF properly after min-on
    sensor.set_temp_c(DEFAULT_SETPOINT_C / 10.0)
    clk.advance(MIN_ON_MS + 1)
    ctrl.step()
    assert_eq(cool.is_on(), False, "fan off")

    # Try to turn ON again before min-off elapsed — should remain OFF
    sensor.set_temp_c((DEFAULT_SETPOINT_C + DEADBAND_TENTHS_C + 5)/10.0)
    clk.advance(MIN_OFF_MS - 200)
    ctrl.step()
    assert_eq(cool.is_on(), False, "fan stays off until min-off elapsed")

    # After min-off elapsed — should turn ON
    clk.advance(500)
    ctrl.step()
    assert_eq(cool.is_on(), True, "fan on after min-off elapsed")

def test_sensor_fault_forces_off_alarm():
    clk = FakeClock(); _inject_clock(clk)
    sensor = MockSensor(initial_tenths=DEFAULT_SETPOINT_C + DEADBAND_TENTHS_C + 20, ok=True)
    cool = MockRelay("COOL"); heat = MockRelay("HEAT")
    ctrl = CoolOnlyController(sensor, cool, heat)

    # should be ON
    ctrl.step()
    assert_eq(cool.is_on(), True, "fan on pre-fault")

    # induce fault
    sensor.fault()
    s = ctrl.step()
    assert_eq(s.alarm, True, "alarm raised on fault")
    assert_eq(cool.is_on(), False, "fan forced off on fault")

def run_all():
    print("Running tests…")
    test_hysteresis_turn_on_off()
    print(" - hysteresis OK")
    test_min_off_prevents_chatter()
    print(" - min-off OK")
    test_sensor_fault_forces_off_alarm()
    print(" - fault handling OK")
    print("All tests passed ✅")
