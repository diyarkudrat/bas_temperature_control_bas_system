# interfaces/actuator.py
# Abstract actuator interface

class Actuator:
    """Abstract interface for actuators (relays, pumps, etc.)."""
    
    def activate(self) -> None:
        """Turn actuator ON."""
        raise NotImplementedError
    
    def deactivate(self) -> None:
        """Turn actuator OFF."""
        raise NotImplementedError
    
    def set_state(self, active: bool) -> None:
        """Set actuator state."""
        if active:
            self.activate()
        else:
            self.deactivate()
    
    def is_active(self) -> bool:
        """Return current state."""
        raise NotImplementedError
    
    @property
    def name(self) -> str:
        """Human-readable actuator name."""
        raise NotImplementedError
    
    def close(self) -> None:
        """Clean up resources."""
        pass
