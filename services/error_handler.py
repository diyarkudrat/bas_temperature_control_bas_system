# services/error_handler.py
# Centralized error handling with fault codes and recovery strategies

from micropython import const
# typing removed for MicroPython
from .logging import Logger, LogLevel, LoggerFactory

class SystemErrorCodes:
    """System-wide error code definitions."""
    
    # Success
    NO_ERROR = const(0)
    
    # Sensor errors (100-199)
    SENSOR_NOT_FOUND = const(101)
    SENSOR_READ_FAILED = const(102)
    SENSOR_INVALID_DATA = const(103)
    SENSOR_STALE_DATA = const(104)
    SENSOR_COMMUNICATION_ERROR = const(105)
    
    # Actuator errors (200-299)
    ACTUATOR_INIT_FAILED = const(201)
    ACTUATOR_STATE_ERROR = const(202)
    ACTUATOR_HARDWARE_FAULT = const(203)
    
    # Controller errors (300-399)
    CONTROLLER_INVALID_STATE = const(301)
    CONTROLLER_CONFIG_ERROR = const(302)
    CONTROLLER_SAFETY_VIOLATION = const(303)
    
    # Network errors (400-499)
    NETWORK_CONNECTION_FAILED = const(401)
    NETWORK_REQUEST_TIMEOUT = const(402)
    NETWORK_INVALID_REQUEST = const(403)
    NETWORK_AUTH_FAILED = const(404)
    NETWORK_RATE_LIMITED = const(405)
    
    # System errors (500-599)
    SYSTEM_OUT_OF_MEMORY = const(501)
    SYSTEM_CONFIG_INVALID = const(502)
    SYSTEM_WATCHDOG_TIMEOUT = const(503)
    SYSTEM_BOOT_FAILED = const(504)
    SYSTEM_UNKNOWN_ERROR = const(599)
    
    # Display errors (600-699)
    DISPLAY_INIT_FAILED = const(601)
    DISPLAY_I2C_ERROR = const(602)
    
    _DESCRIPTIONS = {
        NO_ERROR: "No error",
        SENSOR_NOT_FOUND: "Temperature sensor not found",
        SENSOR_READ_FAILED: "Failed to read sensor data",
        SENSOR_INVALID_DATA: "Invalid sensor data received",
        SENSOR_STALE_DATA: "Sensor data is stale",
        SENSOR_COMMUNICATION_ERROR: "Sensor communication error",
        ACTUATOR_INIT_FAILED: "Actuator initialization failed",
        ACTUATOR_STATE_ERROR: "Actuator in invalid state",
        ACTUATOR_HARDWARE_FAULT: "Actuator hardware fault",
        CONTROLLER_INVALID_STATE: "Controller in invalid state",
        CONTROLLER_CONFIG_ERROR: "Invalid controller configuration",
        CONTROLLER_SAFETY_VIOLATION: "Safety constraint violated",
        NETWORK_CONNECTION_FAILED: "Network connection failed",
        NETWORK_REQUEST_TIMEOUT: "Network request timeout",
        NETWORK_INVALID_REQUEST: "Invalid network request",
        NETWORK_AUTH_FAILED: "Network authentication failed",
        NETWORK_RATE_LIMITED: "Request rate limited",
        SYSTEM_OUT_OF_MEMORY: "System out of memory",
        SYSTEM_CONFIG_INVALID: "System configuration invalid",
        SYSTEM_WATCHDOG_TIMEOUT: "Watchdog timeout",
        SYSTEM_BOOT_FAILED: "System boot failed",
        SYSTEM_UNKNOWN_ERROR: "Unknown system error",
        DISPLAY_INIT_FAILED: "Display initialization failed",
        DISPLAY_I2C_ERROR: "Display I2C communication error"
    }
    
    @classmethod
    def describe(cls, error_code: int) -> str:
        """Get human-readable description of error code."""
        return cls._DESCRIPTIONS.get(error_code, f"Unknown error ({error_code})")
    
    @classmethod
    def is_critical(cls, error_code: int) :
        """Check if error code represents a critical system error."""
        return error_code >= 500 or error_code in [
            cls.CONTROLLER_SAFETY_VIOLATION,
            cls.ACTUATOR_HARDWARE_FAULT
        ]

class SystemError(Exception):
    """Base system error with structured information."""
    
    def __init__(self, error_code: int, message: str = None, component: str = None, context = None):
        self.error_code = error_code
        self.component = component or "UNKNOWN"
        self.context = context or {}
        
        # Use provided message or default description
        self.message = message or SystemErrorCodes.describe(error_code)
        
        super().__init__(f"[{self.component}] {self.message} (code: {error_code})")
    
    def is_critical(self) :
        """Check if this is a critical error."""
        return SystemErrorCodes.is_critical(self.error_code)

class ErrorHandler:
    """Centralized error handling with recovery strategies."""
    
    def __init__(self):
        self._logger = LoggerFactory.get_logger("ErrorHandler")
        self._error_counts = {}
        self._recovery_strategies = {}
        self._last_errors = {}  # component -> last error
        
        # Initialize default recovery strategies
        self._init_recovery_strategies()
    
    def _init_recovery_strategies(self) :
        """Initialize default recovery strategies for different error types."""
        
        def sensor_recovery():
            """Recovery strategy for sensor errors."""
            self._logger.info("Attempting sensor recovery", action="reset_sensor")
            # Would trigger sensor reset in actual implementation
            return True
        
        def actuator_recovery():
            """Recovery strategy for actuator errors."""  
            self._logger.info("Attempting actuator recovery", action="safe_state")
            # Would put actuators in safe state
            return True
        
        def network_recovery():
            """Recovery strategy for network errors."""
            self._logger.info("Network recovery", action="reconnect")
            # Would trigger network reconnection
            return True
        
        # Register recovery strategies
        self._recovery_strategies.update({
            SystemErrorCodes.SENSOR_READ_FAILED: sensor_recovery,
            SystemErrorCodes.SENSOR_COMMUNICATION_ERROR: sensor_recovery,
            SystemErrorCodes.ACTUATOR_STATE_ERROR: actuator_recovery,
            SystemErrorCodes.NETWORK_CONNECTION_FAILED: network_recovery,
            SystemErrorCodes.NETWORK_REQUEST_TIMEOUT: network_recovery,
        })
    
    def handle_error(self, error: SystemError, attempt_recovery: bool = True) :
        """
        Handle system error with logging and optional recovery.
        Returns True if error was handled/recovered, False if critical.
        """
        
        # Increment error count
        self._error_counts[error.error_code] = self._error_counts.get(error.error_code, 0) + 1
        
        # Store last error for component
        self._last_errors[error.component] = error
        
        # Log error with structured data
        log_data = {
            'error_code': error.error_code,
            'component': error.component,
            'count': self._error_counts[error.error_code]
        }
        log_data.update(error.context)
        
        if error.is_critical():
            self._logger.critical(error.message, **log_data)
        else:
            self._logger.error(error.message, **log_data)
        
        # Attempt recovery if requested and strategy exists
        if attempt_recovery and error.error_code in self._recovery_strategies:
            try:
                recovery_fn = self._recovery_strategies[error.error_code]
                if recovery_fn():
                    self._logger.info("Error recovery successful", error_code=error.error_code)
                    return True
                else:
                    self._logger.warning("Error recovery failed", error_code=error.error_code)
            except Exception as e:
                self._logger.error("Error during recovery", error_code=error.error_code, recovery_error=str(e))
        
        # Return false for critical errors that couldn't be recovered
        return not error.is_critical()
    
    def register_recovery_strategy(self, error_code: int, recovery_fn: Callable[[], bool]) :
        """Register custom recovery strategy for error code."""
        self._recovery_strategies[error_code] = recovery_fn
    
    def get_error_stats(self) :
        """Get error statistics for monitoring."""
        return {
            'error_counts': self._error_counts.copy(),
            'last_errors': {
                component: {
                    'error_code': error.error_code,
                    'message': error.message,
                    'context': error.context
                }
                for component, error in self._last_errors.items()
            },
            'total_errors': sum(self._error_counts.values())
        }
    
    def clear_error_stats(self) :
        """Clear error statistics."""
        self._error_counts.clear()
        self._last_errors.clear()
    
    def has_critical_errors(self) :
        """Check if any critical errors have occurred."""
        for error_code in self._error_counts:
            if SystemErrorCodes.is_critical(error_code):
                return True
        return False

# Global error handler instance
_global_error_handler = None

def get_error_handler() -> ErrorHandler:
    """Get global error handler instance."""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler

def handle_error(error_code: int, message: str = None, component: str = None, context = None, attempt_recovery: bool = True) :
    """Convenience function to handle errors."""
    error = SystemError(error_code, message, component, context)
    return get_error_handler().handle_error(error, attempt_recovery)

# Context manager for error handling
class ErrorContext:
    """Context manager for automatic error handling."""
    
    def __init__(self, component: str, operation: str = None):
        self.component = component
        self.operation = operation
        self._logger = LoggerFactory.get_logger(component)
    
    def __enter__(self):
        if self.operation:
            self._logger.debug(f"Starting {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if self.operation:
                self._logger.debug(f"Completed {self.operation}")
            return False
        
        # Convert generic exceptions to SystemError
        if isinstance(exc_val, SystemError):
            error = exc_val
        else:
            # Map common exceptions to system errors
            error_code = SystemErrorCodes.SYSTEM_UNKNOWN_ERROR
            if isinstance(exc_val, MemoryError):
                error_code = SystemErrorCodes.SYSTEM_OUT_OF_MEMORY
            elif isinstance(exc_val, OSError):
                error_code = SystemErrorCodes.SENSOR_COMMUNICATION_ERROR
            
            error = SystemError(
                error_code=error_code,
                message=str(exc_val),
                component=self.component,
                context={'operation': self.operation} if self.operation else {}
            )
        
        # Handle the error
        handled = get_error_handler().handle_error(error)
        
        # Suppress exception if it was handled successfully
        return handled
