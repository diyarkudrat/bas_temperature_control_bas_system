# core/clock.py

import time

# Try to import Clock interface (v2), but don't require it (v1 compatibility)
try:
    from bas.hardware.interfaces import Clock
    _BaseClass = Clock
except ImportError:
    _BaseClass = object

class SystemClock(_BaseClass):
    """System clock implementation using MicroPython time module."""
    
    def now_ms(self) -> int:
        return time.ticks_ms()
    
    def elapsed_ms(self, start_ms: int) -> int:
        return time.ticks_diff(time.ticks_ms(), start_ms)
    
    def sleep_ms(self, ms: int) -> None:
        time.sleep_ms(ms)

# Global instance for backward compatibility
_system_clock = SystemClock()

# Legacy functions for backward compatibility
def now_ms() -> int:
    return _system_clock.now_ms()

def elapsed_ms(start_ms: int) -> int:
    return _system_clock.elapsed_ms(start_ms)