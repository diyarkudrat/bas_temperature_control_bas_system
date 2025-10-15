# tests/sim_loop.py
# Run on Pico REPL:
# >>> import tests.sim_loop as sim; sim.run()

from controller import CoolOnlyController
from config.config import DEFAULT_SETPOINT_C, DEADBAND_TENTHS_C, SAMPLE_PERIOD_MS
import controller as controller_module
from tests.mock_core import FakeClock, MockRelay, MockSensor

def run():
    clk = FakeClock()
    controller_module.now_ms = clk.now_ms
    controller_module.elapsed_ms = clk.elapsed_ms

    sensor = MockSensor(initial_tenths=DEFAULT_SETPOINT_C - 10)
    cool = MockRelay("COOL"); heat = MockRelay("HEAT")
    ctrl = CoolOnlyController(sensor, cool, heat,
                              setpoint_tenths=DEFAULT_SETPOINT_C,
                              deadband_tenths=DEADBAND_TENTHS_C)

    # Simple profile: ramp up, hold, then cool down
    temps_c = [21, 22, 22.5, 23, 23.6, 24.2, 24.0, 23.8, 23.2, 23.0, 22.8, 22.5]

    for t in temps_c:
        sensor.set_temp_c(t)
        s = ctrl.step()
        print({
            "temp_c": None if s.temp_tenths is None else s.temp_tenths/10.0,
            "state": s.state,
            "fan_on": s.fan_on,
            "alarm": s.alarm
        })
        clk.advance(SAMPLE_PERIOD_MS)
