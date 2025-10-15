# core/relay.py
from machine import Pin
try:
    from config.config import RELAY_ACTIVE_HIGH
except (ImportError, AttributeError):
    RELAY_ACTIVE_HIGH = True  # Default to active high

# Try to import Actuator interface (v2), but don't require it (v1 compatibility)
try:
    from interfaces import Actuator
    _BaseClass = Actuator
except ImportError:
    _BaseClass = object

class Relay(_BaseClass):
    """
    Relay abstraction with safe startup and compatibility for all MicroPython builds.
    """
    def __init__(self, pin_num, name="relay"):
        self._name = name
        self._active = 1 if RELAY_ACTIVE_HIGH else 0
        self._inactive = 0 if RELAY_ACTIVE_HIGH else 1

        # Some firmware builds don't allow 'value=' keyword at Pin init.
        # We'll create the Pin first, then immediately set its level.
        self._pin = Pin(pin_num, Pin.OUT)
        self._pin.value(self._inactive)  # ensure inactive level right away

        self._state = False  # logical OFF

    def activate(self):
        """Turn relay ON (implements Actuator interface)."""
        self._pin.value(self._active)
        self._state = True
    
    def deactivate(self):
        """Turn relay OFF (implements Actuator interface)."""
        self._pin.value(self._inactive)
        self._state = False
    
    def is_active(self) -> bool:
        """Return current state (implements Actuator interface)."""
        return self._state
    
    @property
    def name(self) -> str:
        """Human-readable name (implements Actuator interface)."""
        return self._name
    
    # Legacy methods for backward compatibility
    def on(self):
        self.activate()

    def off(self):
        self.deactivate()

    def set(self, state: bool):
        self.set_state(state)

    def is_on(self) -> bool:
        return self.is_active()

    def __repr__(self):
        return f"<Relay {self._name}={'ON' if self._state else 'OFF'}>"
