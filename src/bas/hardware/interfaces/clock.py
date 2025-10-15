# interfaces/clock.py
# Abstract clock interface for timing operations

class Clock:
    """Abstract interface for timing operations."""
    
    def now_ms(self) -> int:
        """Return current time in milliseconds."""
        raise NotImplementedError
    
    def elapsed_ms(self, start_ms: int) -> int:
        """Return elapsed time since start_ms."""
        return self.now_ms() - start_ms
    
    def sleep_ms(self, ms: int) -> None:
        """Sleep for specified milliseconds."""
        raise NotImplementedError
