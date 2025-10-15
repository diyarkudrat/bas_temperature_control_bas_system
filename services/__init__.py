# services/__init__.py
# Services layer for cross-cutting concerns (MicroPython-compatible)

try:
    # Try full-featured versions first (for testing on CPython)
    from .config_manager import ConfigManager, ConfigProfile
except ImportError:
    # Fall back to compatible versions for MicroPython
    from .config_manager_compat import ConfigManager, ConfigProfile

try:
    from .logging import Logger, LogLevel, LoggerFactory
except ImportError:
    # Simple fallback logger
    class LogLevel:
        DEBUG = 10
        INFO = 20
        WARNING = 30
        ERROR = 40
    
    class Logger:
        def __init__(self, component, level=20):
            self.component = component
        def debug(self, msg, **kwargs): pass
        def info(self, msg, **kwargs): print(f"[{self.component}] {msg}")
        def warning(self, msg, **kwargs): print(f"[{self.component}] WARNING: {msg}")
        def error(self, msg, **kwargs): print(f"[{self.component}] ERROR: {msg}")
    
    class LoggerFactory:
        _loggers = {}
        @classmethod
        def get_logger(cls, component):
            if component not in cls._loggers:
                cls._loggers[component] = Logger(component)
            return cls._loggers[component]

try:
    from .error_handler import ErrorHandler, SystemError, SystemErrorCodes, handle_error, ErrorContext
except ImportError:
    # Simple error codes
    class SystemErrorCodes:
        NO_ERROR = 0
        SENSOR_READ_FAILED = 102
        CONTROLLER_CONFIG_ERROR = 302
        NETWORK_CONNECTION_FAILED = 401
        SYSTEM_OUT_OF_MEMORY = 501
        DISPLAY_INIT_FAILED = 601
        SYSTEM_BOOT_FAILED = 504
        ACTUATOR_INIT_FAILED = 201
        CONTROLLER_INVALID_STATE = 301
        DISPLAY_I2C_ERROR = 602
        SYSTEM_UNKNOWN_ERROR = 599
    
    class SystemError(Exception):
        def __init__(self, error_code, message=None, component=None, context=None):
            self.error_code = error_code
            self.message = message or f"Error {error_code}"
            self.component = component or "UNKNOWN"
            self.context = context or {}
            super().__init__(self.message)
    
    class ErrorHandler:
        def __init__(self): pass
        def handle_error(self, error, attempt_recovery=True):
            print(f"[{error.component}] Error {error.error_code}: {error.message}")
            return True
    
    # Simple fallback for handle_error function
    def handle_error(error_code, message=None, component=None, context=None, attempt_recovery=True):
        error = SystemError(error_code, message, component, context)
        print(f"[{error.component}] Error {error_code}: {error.message}")
        return True
    
    # Simple fallback for ErrorContext
    class ErrorContext:
        def __init__(self, component, operation=None):
            self.component = component
            self.operation = operation
        
        def __enter__(self):
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is not None:
                print(f"[{self.component}] Error in {self.operation}: {exc_val}")
            return False  # Don't suppress exceptions

__all__ = [
    'ConfigManager', 'ConfigProfile',
    'Logger', 'LogLevel', 'LoggerFactory',
    'SystemError', 'SystemErrorCodes', 'ErrorHandler', 'handle_error', 'ErrorContext'
]
