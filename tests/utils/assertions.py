"""
Enhanced assertion utilities for better test error messages.
"""

from typing import Any, Optional
import builtins


def assert_equals(actual: Any, expected: Any, message: str = "") -> None:
    """Enhanced equality assertion with detailed error message."""
    if actual != expected:
        error_msg = f"{message}: expected {expected}, got {actual}"
        if message:
            error_msg = f"{message}\n  Expected: {expected}\n  Actual: {actual}"
        raise AssertionError(error_msg)


def assert_not_equals(actual: Any, expected: Any, message: str = "") -> None:
    """Enhanced inequality assertion with detailed error message."""
    if actual == expected:
        error_msg = f"{message}: expected values to be different, but both were {actual}"
        raise AssertionError(error_msg)


def assert_true(condition: bool, message: str = "") -> None:
    """Enhanced truth assertion with detailed error message."""
    if not condition:
        error_msg = f"{message}: expected True, got False"
        if not message:
            error_msg = "Expected condition to be True, but it was False"
        raise AssertionError(error_msg)


def assert_false(condition: bool, message: str = "") -> None:
    """Enhanced falsity assertion with detailed error message."""
    if condition:
        error_msg = f"{message}: expected False, got True"
        if not message:
            error_msg = "Expected condition to be False, but it was True"
        raise AssertionError(error_msg)


def assert_is_none(value: Any, message: str = "") -> None:
    """Enhanced None assertion with detailed error message."""
    if value is not None:
        error_msg = f"{message}: expected None, got {value}"
        if not message:
            error_msg = f"Expected None, but got {value}"
        raise AssertionError(error_msg)

# Expose commonly used assertions via builtins for convenience in tests that
# omit explicit imports (legacy pattern in some test files).
builtins.assert_is_none = assert_is_none


def assert_is_not_none(value: Any, message: str = "") -> None:
    """Enhanced not-None assertion with detailed error message."""
    if value is None:
        error_msg = f"{message}: expected non-None value, got None"
        if not message:
            error_msg = "Expected non-None value, but got None"
        raise AssertionError(error_msg)


def assert_contains(container: Any, item: Any, message: str = "") -> None:
    """Enhanced contains assertion with detailed error message."""
    if item not in container:
        error_msg = f"{message}: expected {item} to be in {container}"
        if not message:
            error_msg = f"Expected {item} to be contained in {container}"
        raise AssertionError(error_msg)


def assert_not_contains(container: Any, item: Any, message: str = "") -> None:
    """Enhanced not-contains assertion with detailed error message."""
    if item in container:
        error_msg = f"{message}: expected {item} not to be in {container}"
        if not message:
            error_msg = f"Expected {item} not to be contained in {container}"
        raise AssertionError(error_msg)


def assert_is_instance(obj: Any, expected_type: type, message: str = "") -> None:
    """Enhanced isinstance assertion with detailed error message."""
    if not isinstance(obj, expected_type):
        actual_type = type(obj).__name__
        expected_type_name = expected_type.__name__
        error_msg = f"{message}: expected instance of {expected_type_name}, got {actual_type}"
        if not message:
            error_msg = f"Expected instance of {expected_type_name}, got {actual_type}"
        raise AssertionError(error_msg)


def assert_raises(expected_exception: type, message: str = ""):
    """Context manager for testing exceptions with detailed error messages."""
    class ExceptionAssertion:
        def __init__(self, exception_type: type, msg: str):
            self.exception_type = exception_type
            self.message = msg
            self.exception = None
            self.value = None  # Add value property for compatibility
            
        def __enter__(self):
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                error_msg = f"{self.message}: expected {self.exception_type.__name__} to be raised"
                if not self.message:
                    error_msg = f"Expected {self.exception_type.__name__} to be raised"
                raise AssertionError(error_msg)
            
            if not issubclass(exc_type, self.exception_type):
                error_msg = f"{self.message}: expected {self.exception_type.__name__}, got {exc_type.__name__}: {exc_val}"
                if not self.message:
                    error_msg = f"Expected {self.exception_type.__name__}, got {exc_type.__name__}: {exc_val}"
                raise AssertionError(error_msg)
            
            self.exception = exc_val
            self.value = exc_val  # Set value property for compatibility
            return True  # Suppress the exception
    
    return ExceptionAssertion(expected_exception, message)
