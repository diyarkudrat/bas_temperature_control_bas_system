# services/logging.py
# Lightweight structured logging for MicroPython

import time
from micropython import const

class LogLevel:
    """Log level constants."""
    DEBUG = const(10)
    INFO = const(20)
    WARNING = const(30)
    ERROR = const(40)
    CRITICAL = const(50)
    
    _NAMES = {
        DEBUG: "DEBUG",
        INFO: "INFO", 
        WARNING: "WARN",
        ERROR: "ERROR",
        CRITICAL: "CRIT"
    }
    
    @classmethod
    def name(cls, level: int) -> str:
        return cls._NAMES.get(level, "UNKNOWN")

class LogEntry:
    """Single log entry."""
    __slots__ = ('timestamp_ms', 'level', 'component', 'message', 'data')
    
    def __init__(self, timestamp_ms: int, level: int, component: str, message: str, data: dict = None):
        self.timestamp_ms = timestamp_ms
        self.level = level
        self.component = component
        self.message = message
        self.data = data or {}
    
    def format(self) -> str:
        """Format log entry as string."""
        # Simple format: TIMESTAMP LEVEL COMPONENT: MESSAGE {data}
        data_str = ""
        if self.data:
            # Simple key=value format to avoid JSON overhead
            items = [f"{k}={v}" for k, v in self.data.items()]
            data_str = f" {{{', '.join(items)}}}"
        
        return f"{self.timestamp_ms:010d} {LogLevel.name(self.level):5s} {self.component}: {self.message}{data_str}"

class RingBuffer:
    """Fixed-size ring buffer for log entries."""
    
    def __init__(self, capacity: int = 100):
        self._capacity = capacity
        self._buffer = [None] * capacity
        self._index = 0
        self._size = 0
    
    def append(self, entry: LogEntry) :
        """Add entry to buffer."""
        self._buffer[self._index] = entry
        self._index = (self._index + 1) % self._capacity
        if self._size < self._capacity:
            self._size += 1
    
    def get_recent(self, count: int = None) -> list:
        """Get recent entries (newest first)."""
        if count is None:
            count = self._size
        
        count = min(count, self._size)
        if count == 0:
            return []
        
        entries = []
        # Start from most recent and work backwards
        idx = (self._index - 1) % self._capacity
        for _ in range(count):
            if self._buffer[idx] is not None:
                entries.append(self._buffer[idx])
            idx = (idx - 1) % self._capacity
        
        return entries
    
    def clear(self) :
        """Clear all entries."""
        self._buffer = [None] * self._capacity
        self._index = 0
        self._size = 0

class Logger:
    """Lightweight logger with ring buffer and structured data."""
    
    def __init__(self, component: str, level: int = LogLevel.INFO, buffer_size: int = 100):
        self.component = component
        self.level = level
        self._buffer = RingBuffer(buffer_size)
        self._print_enabled = True
    
    def set_level(self, level: int) :
        """Set minimum log level."""
        self.level = level
    
    def set_print_enabled(self, enabled: bool) :
        """Enable/disable console output."""
        self._print_enabled = enabled
    
    def _log(self, level: int, message: str, **kwargs) :
        """Internal logging method."""
        if level < self.level:
            return
        
        entry = LogEntry(
            timestamp_ms=time.ticks_ms(),
            level=level,
            component=self.component,
            message=message,
            data=kwargs
        )
        
        # Store in ring buffer
        self._buffer.append(entry)
        
        # Print to console if enabled
        if self._print_enabled:
            print(entry.format())
    
    def debug(self, message: str, **kwargs) :
        """Log debug message."""
        self._log(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) :
        """Log info message."""
        self._log(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) :
        """Log warning message."""
        self._log(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) :
        """Log error message."""
        self._log(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) :
        """Log critical message."""
        self._log(LogLevel.CRITICAL, message, **kwargs)
    
    def get_recent_logs(self, count: int = 50) -> list:
        """Get recent log entries."""
        return self._buffer.get_recent(count)
    
    def clear_logs(self) :
        """Clear log buffer."""
        self._buffer.clear()
    
    # Context manager support for structured logging
    def context(self, **context_data):
        """Return a context logger with additional data."""
        return ContextLogger(self, context_data)

class ContextLogger:
    """Logger wrapper that adds context data to all log calls."""
    
    def __init__(self, logger: Logger, context_data: dict):
        self._logger = logger
        self._context = context_data
    
    def _merge_data(self, **kwargs):
        """Merge context data with call-specific data."""
        merged = self._context.copy()
        merged.update(kwargs)
        return merged
    
    def debug(self, message: str, **kwargs) :
        self._logger.debug(message, **self._merge_data(**kwargs))
    
    def info(self, message: str, **kwargs) :
        self._logger.info(message, **self._merge_data(**kwargs))
    
    def warning(self, message: str, **kwargs) :
        self._logger.warning(message, **self._merge_data(**kwargs))
    
    def error(self, message: str, **kwargs) :
        self._logger.error(message, **self._merge_data(**kwargs))
    
    def critical(self, message: str, **kwargs) :
        self._logger.critical(message, **self._merge_data(**kwargs))

# Global logger factory
class LoggerFactory:
    """Factory for creating component loggers."""
    
    _loggers = {}
    _global_level = LogLevel.INFO
    
    @classmethod
    def get_logger(cls, component: str) -> Logger:
        """Get or create logger for component."""
        if component not in cls._loggers:
            cls._loggers[component] = Logger(component, cls._global_level)
        return cls._loggers[component]
    
    @classmethod
    def set_global_level(cls, level: int) :
        """Set log level for all loggers."""
        cls._global_level = level
        for logger in cls._loggers.values():
            logger.set_level(level)
    
    @classmethod
    def set_print_enabled(cls, enabled: bool) :
        """Enable/disable console output for all loggers."""
        for logger in cls._loggers.values():
            logger.set_print_enabled(enabled)
