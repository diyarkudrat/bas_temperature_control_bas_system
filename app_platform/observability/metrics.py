class AuthMetrics:
    """Authentication metrics."""

    def __init__(self) -> None:
        """Initialize the AuthMetrics."""
        
        self._counters: dict[str, int] = {}

    def incr(self, name: str, value: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + int(value)

    def get(self, name: str) -> int:
        return int(self._counters.get(name, 0))


