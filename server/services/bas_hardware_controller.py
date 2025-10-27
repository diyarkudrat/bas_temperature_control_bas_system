"""
Hardware controller for BAS.

Encapsulates temperature control logic used by the server routes. Keeps
mutable state of current readings and actuator decisions, with simple
minimum on/off timing to protect hardware. Stateless APIs read from and
mutate the instance state; the object is expected to be process-local.
"""

from __future__ import annotations

import time


class BASController:
    """Temperature control logic with minimal safety timing.

    - Maintains setpoint and deadband
    - Uses minimum on/off times to avoid relay thrash
    - Always keeps LED (heat relay) on per current hardware semantics
    """

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
        """Update control logic based on sensor reading.

        Applies deadband and minimum on/off timing for cooling. Heat relay
        (LEDs) remains on as per existing behavior.
        """
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
        """Set temperature setpoint in tenths of a degree."""
        if 100 <= setpoint_tenths <= 400:  # 10.0°C to 40.0°C
            self.setpoint_tenths = setpoint_tenths
            return True
        return False

    def set_deadband(self, deadband_tenths):
        """Set temperature deadband in tenths of a degree."""
        if 0 <= deadband_tenths <= 50:  # 0.0°C to 5.0°C
            self.deadband_tenths = deadband_tenths
            return True
        return False


