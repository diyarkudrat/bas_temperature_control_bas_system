# tests/test_services.py
# Tests for services layer (config management, logging, error handling)

try:
    import ujson as json
except Exception:
    import json
import time
from services import ConfigManager, ConfigProfile, Logger, LogLevel, ErrorHandler, SystemError, SystemErrorCodes, LoggerFactory

# Test utilities
def assert_eq(actual, expected, message=""):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected}, got {actual}")

def assert_true(condition, message=""):
    if not condition:
        raise AssertionError(f"{message}: condition was false")

def assert_false(condition, message=""):
    if condition:
        raise AssertionError(f"{message}: condition was true")

def assert_raises(exception_type, callable_obj, *args, **kwargs):
    try:
        callable_obj(*args, **kwargs)
        raise AssertionError(f"Expected {exception_type.__name__} to be raised")
    except exception_type:
        pass  # Expected
    except Exception as e:
        raise AssertionError(f"Expected {exception_type.__name__}, got {type(e).__name__}: {e}")

class TestConfigProfile:
    """Test configuration profile validation and serialization."""
    
    def test_default_profile_creation(self):
        """Test creating profile with defaults."""
        profile = ConfigProfile("test")
        
        assert_eq(profile.profile_name, "test", "Profile name should match")
        assert_eq(profile.setpoint_tenths, 230, "Default setpoint should be 230")
        assert_eq(profile.deadband_tenths, 5, "Default deadband should be 5")
        assert_true(profile.cool_only, "Should be cool-only by default")
        
        print("✓ Default profile creation test passed")
    
    def test_profile_validation_valid(self):
        """Test validation of valid configuration."""
        profile = ConfigProfile("valid")
        profile.setpoint_tenths = 250  # 25.0°C
        profile.deadband_tenths = 10   # 1.0°C
        profile.sample_period_ms = 2000
        profile.min_on_ms = 5000
        profile.min_off_ms = 5000
        
        # Should not raise exception
        profile.validate()
        
        print("✓ Valid profile validation test passed")
    
    def test_profile_validation_invalid_temperature(self):
        """Test validation with invalid temperature values."""
        profile = ConfigProfile("invalid")
        
        # Invalid setpoint (too high)
        profile.setpoint_tenths = 1000  # 100°C - too hot
        assert_raises(Exception, profile.validate)
        
        # Invalid setpoint (too low)
        profile.setpoint_tenths = -500  # -50°C - too cold
        assert_raises(Exception, profile.validate)
        
        # Reset to valid
        profile.setpoint_tenths = 230
        
        # Invalid deadband (too large)
        profile.deadband_tenths = 200  # 20°C - too large
        assert_raises(Exception, profile.validate)
        
        print("✓ Invalid temperature validation test passed")
    
    def test_profile_validation_invalid_timing(self):
        """Test validation with invalid timing values.""" 
        profile = ConfigProfile("invalid")
        
        # Invalid sample period (too fast)
        profile.sample_period_ms = 50  # Too fast
        assert_raises(Exception, profile.validate)
        
        # Invalid min_on (too short)
        profile.sample_period_ms = 2000  # Reset
        profile.min_on_ms = 500  # Too short
        assert_raises(Exception, profile.validate)
        
        print("✓ Invalid timing validation test passed")
    
    def test_profile_serialization(self):
        """Test profile to/from dictionary conversion."""
        profile = ConfigProfile("serialize_test")
        profile.setpoint_tenths = 240
        profile.deadband_tenths = 15
        profile.enable_debug_logs = True
        
        # Convert to dict
        data = profile.to_dict()
        assert_eq(data['profile_name'], "serialize_test", "Name should serialize")
        assert_eq(data['setpoint_tenths'], 240, "Setpoint should serialize")
        assert_eq(data['enable_debug_logs'], True, "Boolean should serialize")
        
        # Convert back from dict
        profile2 = ConfigProfile.from_dict(data)
        assert_eq(profile2.profile_name, profile.profile_name, "Names should match")
        assert_eq(profile2.setpoint_tenths, profile.setpoint_tenths, "Setpoints should match")
        assert_eq(profile2.enable_debug_logs, profile.enable_debug_logs, "Booleans should match")
        
        print("✓ Profile serialization test passed")

class TestConfigManager:
    """Test configuration manager functionality."""
    
    def test_default_profiles(self):
        """Test built-in default profiles."""
        manager = ConfigManager()
        
        profiles = manager.list_profiles()
        assert_true("default" in profiles, "Should have default profile")
        assert_true("development" in profiles, "Should have development profile")
        assert_true("high_temp" in profiles, "Should have high_temp profile")
        
        # Test getting current profile (should be default)
        current = manager.get_current_profile()
        assert_eq(current.profile_name, "default", "Current should be default")
        
        print("✓ Default profiles test passed")
    
    def test_profile_switching(self):
        """Test switching between profiles."""
        manager = ConfigManager()
        
        # Switch to development profile
        result = manager.set_profile("development")
        assert_true(result, "Should successfully switch to development")
        
        current = manager.get_current_profile()
        assert_eq(current.profile_name, "development", "Current should be development")
        
        # Try to switch to non-existent profile
        result = manager.set_profile("nonexistent")
        assert_false(result, "Should fail to switch to nonexistent profile")
        
        # Current should remain unchanged
        current = manager.get_current_profile()
        assert_eq(current.profile_name, "development", "Current should remain development")
        
        print("✓ Profile switching test passed")
    
    def test_runtime_config_updates(self):
        """Test runtime configuration updates."""
        manager = ConfigManager()
        
        # Update valid parameters
        result = manager.update_runtime_config(
            setpoint_tenths=250,
            deadband_tenths=12,
            enable_debug_logs=True
        )
        assert_true(result, "Should successfully update runtime config")
        
        current = manager.get_current_profile()
        assert_eq(current.setpoint_tenths, 250, "Setpoint should update")
        assert_eq(current.deadband_tenths, 12, "Deadband should update")
        assert_true(current.enable_debug_logs, "Debug logs should update")
        
        # Try to update non-runtime parameter (should be ignored)
        result = manager.update_runtime_config(
            pin_relay_cool=99  # Hardware config - not runtime tunable
        )
        assert_true(result, "Should succeed but ignore non-runtime params")
        
        # Pin should remain unchanged
        assert_eq(current.pin_relay_cool, 15, "Hardware pin should not change")
        
        print("✓ Runtime config updates test passed")
    
    def test_profile_summary(self):
        """Test profile summary generation."""
        manager = ConfigManager()
        
        summary = manager.get_profile_summary()
        
        # Check expected fields
        assert_true('profile_name' in summary, "Should include profile name")
        assert_true('setpoint_c' in summary, "Should include setpoint in Celsius")
        assert_true('available_profiles' in summary, "Should include available profiles")
        
        # Check value conversion
        profile = manager.get_current_profile()
        expected_setpoint_c = profile.setpoint_tenths / 10.0
        assert_eq(summary['setpoint_c'], expected_setpoint_c, "Setpoint should convert to Celsius")
        
        print("✓ Profile summary test passed")

class TestLogging:
    """Test logging functionality."""
    
    def test_logger_creation(self):
        """Test logger creation and basic functionality."""
        logger = Logger("TestComponent", LogLevel.INFO)
        
        assert_eq(logger.component, "TestComponent", "Component name should match")
        assert_eq(logger.level, LogLevel.INFO, "Log level should match")
        
        print("✓ Logger creation test passed")
    
    def test_log_levels(self):
        """Test log level filtering."""
        logger = Logger("TestLevels", LogLevel.WARNING)
        logger.set_print_enabled(False)  # Disable console output for tests
        
        # These should be logged (>= WARNING)
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")
        
        # These should be filtered out (< WARNING)
        logger.debug("Debug message")
        logger.info("Info message")
        
        # Check that only 3 messages were logged
        recent_logs = logger.get_recent_logs(10)
        assert_eq(len(recent_logs), 3, "Should have 3 log entries")
        
        # Check log levels
        levels = [entry.level for entry in recent_logs]
        assert_true(LogLevel.WARNING in levels, "Should have warning")
        assert_true(LogLevel.ERROR in levels, "Should have error")
        assert_true(LogLevel.CRITICAL in levels, "Should have critical")
        
        print("✓ Log levels test passed")
    
    def test_structured_logging(self):
        """Test structured logging with data."""
        logger = Logger("TestStructured", LogLevel.DEBUG)
        logger.set_print_enabled(False)
        
        # Log with structured data
        logger.info("Test message", temperature=23.5, sensor_ok=True, count=42)
        
        recent_logs = logger.get_recent_logs(1)
        assert_eq(len(recent_logs), 1, "Should have 1 log entry")
        
        entry = recent_logs[0]
        assert_eq(entry.message, "Test message", "Message should match")
        assert_eq(entry.data['temperature'], 23.5, "Temperature data should match")
        assert_eq(entry.data['sensor_ok'], True, "Boolean data should match")
        assert_eq(entry.data['count'], 42, "Count data should match")
        
        print("✓ Structured logging test passed")
    
    def test_ring_buffer(self):
        """Test ring buffer behavior."""
        # Small buffer for testing
        logger = Logger("TestRingBuffer", LogLevel.DEBUG, buffer_size=3)
        logger.set_print_enabled(False)
        
        # Fill buffer beyond capacity
        logger.info("Message 1")
        logger.info("Message 2")
        logger.info("Message 3")
        logger.info("Message 4")  # Should overwrite Message 1
        logger.info("Message 5")  # Should overwrite Message 2
        
        recent_logs = logger.get_recent_logs(10)
        assert_eq(len(recent_logs), 3, "Buffer should be limited to 3 entries")
        
        # Check that oldest messages were overwritten (newest first)
        messages = [entry.message for entry in recent_logs]
        assert_eq(messages[0], "Message 5", "Newest should be first")
        assert_eq(messages[1], "Message 4", "Second newest")
        assert_eq(messages[2], "Message 3", "Third newest")
        
        print("✓ Ring buffer test passed")

    def test_per_logger_overrides(self):
        """Test per-logger level/print overrides vs global controls."""
        # Create two component loggers via factory
        a = LoggerFactory.get_logger("A")
        b = LoggerFactory.get_logger("B")
        a.set_print_enabled(False)
        b.set_print_enabled(False)

        # Start with a global INFO
        LoggerFactory.set_global_level(LogLevel.INFO)
        assert_eq(a.level, LogLevel.INFO, "A should follow global INFO")
        assert_eq(b.level, LogLevel.INFO, "B should follow global INFO")

        # Override B to ERROR; raise global to DEBUG. B should remain ERROR.
        LoggerFactory.override_level("B", LogLevel.ERROR)
        LoggerFactory.set_global_level(LogLevel.DEBUG)
        assert_eq(a.level, LogLevel.DEBUG, "A follows global DEBUG")
        assert_eq(b.level, LogLevel.ERROR, "B keeps overridden ERROR")

        # Override print on A only; then globally disable print. A stays as set, B follows global.
        LoggerFactory.override_print("A", True)
        LoggerFactory.set_print_enabled(False)
        assert_true(a._print_enabled, "A print remains True due to override")
        assert_false(b._print_enabled, "B print follows global False")

        print("✓ Per-logger overrides test passed")

    def test_clear_overrides_and_sync(self):
        """Clearing overrides should sync logger back to global settings."""
        c = LoggerFactory.get_logger("C")
        c.set_print_enabled(False)
        LoggerFactory.set_global_level(LogLevel.WARNING)
        LoggerFactory.override_level("C", LogLevel.ERROR)
        assert_eq(c.level, LogLevel.ERROR, "C level overridden to ERROR")

        # Clear override -> should adopt current global (WARNING)
        LoggerFactory.clear_level_override("C")
        assert_eq(c.level, LogLevel.WARNING, "C level synced back to global WARNING")

        # Print override
        LoggerFactory.override_print("C", True)
        assert_true(c._print_enabled, "C print True overridden")
        # Set global False and clear override -> should become False
        LoggerFactory.set_print_enabled(False)
        LoggerFactory.clear_print_override("C")
        assert_false(c._print_enabled, "C print synced back to global False")

        print("✓ Clear overrides sync test passed")

class TestErrorHandler:
    """Test error handling functionality."""
    
    def test_error_creation(self):
        """Test SystemError creation."""
        error = SystemError(
            error_code=SystemErrorCodes.SENSOR_READ_FAILED,
            message="Custom message",
            component="TestComponent",
            context={"sensor_id": 1, "retry_count": 3}
        )
        
        assert_eq(error.error_code, SystemErrorCodes.SENSOR_READ_FAILED, "Error code should match")
        assert_eq(error.message, "Custom message", "Message should match")
        assert_eq(error.component, "TestComponent", "Component should match")
        assert_eq(error.context['sensor_id'], 1, "Context should be preserved")
        
        print("✓ Error creation test passed")
    
    def test_error_criticality(self):
        """Test error criticality detection."""
        # Non-critical error
        sensor_error = SystemError(SystemErrorCodes.SENSOR_READ_FAILED)
        assert_false(sensor_error.is_critical(), "Sensor error should not be critical")
        
        # Critical error
        safety_error = SystemError(SystemErrorCodes.CONTROLLER_SAFETY_VIOLATION)
        assert_true(safety_error.is_critical(), "Safety violation should be critical")
        
        system_error = SystemError(SystemErrorCodes.SYSTEM_OUT_OF_MEMORY)
        assert_true(system_error.is_critical(), "System error should be critical")
        
        print("✓ Error criticality test passed")
    
    def test_error_handler_stats(self):
        """Test error handler statistics."""
        handler = ErrorHandler()
        
        # Handle some errors
        error1 = SystemError(SystemErrorCodes.SENSOR_READ_FAILED, component="Sensor")
        error2 = SystemError(SystemErrorCodes.SENSOR_READ_FAILED, component="Sensor")  # Same type
        error3 = SystemError(SystemErrorCodes.NETWORK_CONNECTION_FAILED, component="Network")
        
        handler.handle_error(error1, attempt_recovery=False)
        handler.handle_error(error2, attempt_recovery=False)
        handler.handle_error(error3, attempt_recovery=False)
        
        # Check statistics
        stats = handler.get_error_stats()
        
        assert_eq(stats['total_errors'], 3, "Total errors should be 3")
        assert_eq(stats['error_counts'][SystemErrorCodes.SENSOR_READ_FAILED], 2, "Sensor errors should be 2")
        assert_eq(stats['error_counts'][SystemErrorCodes.NETWORK_CONNECTION_FAILED], 1, "Network errors should be 1")
        
        # Check last errors per component
        assert_true('Sensor' in stats['last_errors'], "Should track last sensor error")
        assert_true('Network' in stats['last_errors'], "Should track last network error")
        
        print("✓ Error handler stats test passed")
    
    def test_critical_error_detection(self):
        """Test critical error detection in handler."""
        handler = ErrorHandler()
        
        # Handle non-critical error
        non_critical = SystemError(SystemErrorCodes.SENSOR_READ_FAILED)
        handler.handle_error(non_critical, attempt_recovery=False)
        assert_false(handler.has_critical_errors(), "Should not have critical errors")
        
        # Handle critical error
        critical = SystemError(SystemErrorCodes.SYSTEM_OUT_OF_MEMORY)
        handler.handle_error(critical, attempt_recovery=False)
        assert_true(handler.has_critical_errors(), "Should have critical errors")
        
        print("✓ Critical error detection test passed")

class TestIntegration:
    """Integration tests for services working together."""
    
    def test_config_and_logging_integration(self):
        """Test configuration affecting logging behavior."""
        manager = ConfigManager()
        
        # Enable debug logging through config
        manager.update_runtime_config(enable_debug_logs=True)
        
        # Create logger (would use global config in real system)
        logger = Logger("Integration", LogLevel.DEBUG)
        logger.set_print_enabled(False)
        
        # Log at debug level
        logger.debug("Debug message")
        
        recent_logs = logger.get_recent_logs(1)
        assert_eq(len(recent_logs), 1, "Debug message should be logged")
        
        print("✓ Config and logging integration test passed")
    
    def test_error_and_logging_integration(self):
        """Test error handling with logging."""
        handler = ErrorHandler()
        
        # Handle error (should log automatically)
        error = SystemError(
            SystemErrorCodes.CONTROLLER_CONFIG_ERROR,
            "Test integration error",
            "Integration"
        )
        
        result = handler.handle_error(error, attempt_recovery=False)
        
        # Non-critical error should be handled
        assert_true(result, "Non-critical error should be handled")
        
        print("✓ Error and logging integration test passed")

def run_all_services_tests():
    """Run all services tests."""
    print("Running Services Tests...")
    print("=" * 50)
    
    # Config Profile tests
    profile_tests = TestConfigProfile()
    profile_tests.test_default_profile_creation()
    profile_tests.test_profile_validation_valid()
    profile_tests.test_profile_validation_invalid_temperature()
    profile_tests.test_profile_validation_invalid_timing()
    profile_tests.test_profile_serialization()
    
    # Config Manager tests
    manager_tests = TestConfigManager()
    manager_tests.test_default_profiles()
    manager_tests.test_profile_switching()
    manager_tests.test_runtime_config_updates()
    manager_tests.test_profile_summary()
    
    # Logging tests
    logging_tests = TestLogging()
    logging_tests.test_logger_creation()
    logging_tests.test_log_levels()
    logging_tests.test_structured_logging()
    logging_tests.test_ring_buffer()
    logging_tests.test_per_logger_overrides()
    logging_tests.test_clear_overrides_and_sync()
    
    # Error Handler tests
    error_tests = TestErrorHandler()
    error_tests.test_error_creation()
    error_tests.test_error_criticality()
    error_tests.test_error_handler_stats()
    error_tests.test_critical_error_detection()
    
    # Integration tests
    integration_tests = TestIntegration()
    integration_tests.test_config_and_logging_integration()
    integration_tests.test_error_and_logging_integration()
    
    print("=" * 50)
    print("All Services tests passed! ✅")

if __name__ == "__main__":
    run_all_services_tests()
