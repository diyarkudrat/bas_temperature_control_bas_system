"""
Hardware controller for BAS (migrated).
"""

from __future__ import annotations

import time


class BASController:
    def __init__(self):
        self.setpoint_tenths = 230
        self.deadband_tenths = 10
        self.min_on_time_ms = 10000
        self.min_off_time_ms = 10000
        self.last_cool_on_time = 0
        self.last_cool_off_time = 0
        self.last_heat_on_time = 0
        self.last_heat_off_time = 0
        self.current_temp_tenths = 0
        self.sensor_ok = False
        self.cool_active = False
        self.heat_active = False
        self.state = "IDLE"

    def update_control(self, temp_tenths, sensor_ok):
        self.current_temp_tenths = temp_tenths
        self.sensor_ok = sensor_ok
        if not sensor_ok:
            self.cool_active = False
            self.heat_active = False
            self.state = "FAULT"
            return
        current_time = time.time() * 1000
        should_cool = temp_tenths > (self.setpoint_tenths + self.deadband_tenths)
        self.heat_active = True
        if self.cool_active:
            if not should_cool and (current_time - self.last_cool_on_time) >= self.min_on_time_ms:
                self.cool_active = False
                self.last_cool_off_time = current_time
        else:
            if should_cool and (current_time - self.last_cool_off_time) >= self.min_off_time_ms:
                self.cool_active = True
                self.last_cool_on_time = current_time
        if self.cool_active and self.heat_active:
            self.state = "COOLING_WITH_LEDS"
        elif self.cool_active:
            self.state = "COOLING"
        elif self.heat_active:
            self.state = "IDLE_WITH_LEDS"
        else:
            self.state = "IDLE"

    def get_control_commands(self):
        return {
            "cool_active": self.cool_active,
            "heat_active": self.heat_active,
            "setpoint_tenths": self.setpoint_tenths,
            "deadband_tenths": self.deadband_tenths,
        }

    def set_setpoint(self, setpoint_tenths):
        if 100 <= setpoint_tenths <= 400:
            self.setpoint_tenths = setpoint_tenths
            return True
        return False

    def set_deadband(self, deadband_tenths):
        if 0 <= deadband_tenths <= 50:
            self.deadband_tenths = deadband_tenths
            return True
        return False


