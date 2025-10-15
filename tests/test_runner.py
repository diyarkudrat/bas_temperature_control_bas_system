# tests/test_runner.py
# Comprehensive test runner with performance and stress testing

import time
import gc
from typing import List, Dict, Any, Callable

# Import all test modules
try:
    from tests.test_controller_v2 import run_all_tests as run_controller_tests
    from tests.test_services import run_all_services_tests
    from tests.mock_interfaces import MockClock, MockActuator, MockTemperatureSensor
    from controller import CoolOnlyController
    from services import LoggerFactory
except ImportError as e:
    print(f"Warning: Some test modules could not be imported: {e}")

class TestResult:
    """Test result container."""
    
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.duration_ms = 0
        self.memory_used = 0
        self.error_message = ""
        self.start_time = 0
        self.start_memory = 0
    
    def start(self):
        """Start timing and memory measurement."""
        gc.collect()  # Clean up before measurement
        self.start_time = time.ticks_ms()
        self.start_memory = gc.mem_alloc()
    
    def finish(self, passed: bool, error_message: str = ""):
        """Finish timing and memory measurement."""
        self.duration_ms = time.ticks_diff(time.ticks_ms(), self.start_time)
        self.memory_used = gc.mem_alloc() - self.start_memory
        self.passed = passed
        self.error_message = error_message

class PerformanceTest:
    """Performance and stress testing."""
    
    def __init__(self):
        self.results: List[TestResult] = []
    
    def run_controller_performance_test(self) -> TestResult:
        """Test controller performance under load."""
        result = TestResult("Controller Performance")
        result.start()
        
        try:
            clock = MockClock()
            sensor = MockTemperatureSensor(clock, initial_temp_tenths=230)
            cool_actuator = MockActuator("COOL")
            heat_actuator = MockActuator("HEAT")
            
            controller = CoolOnlyController(
                sensor=sensor,
                cool_actuator=cool_actuator,
                heat_actuator=heat_actuator,
                clock=clock,
                setpoint_tenths=230,
                deadband_tenths=10,
                min_on_ms=1000,  # Shorter for faster testing
                min_off_ms=1000
            )
            
            # Run many controller steps
            num_steps = 1000
            for i in range(num_steps):
                # Vary temperature
                temp_offset = (i % 100) - 50  # -50 to +49 tenths
                sensor.set_temperature_c((230 + temp_offset) / 10.0)
                
                # Advance time
                clock.advance(100)
                
                # Execute controller step
                status = controller.step()
                
                # Verify basic operation
                if not hasattr(status, 'state'):
                    raise AssertionError(f"Invalid status at step {i}")
            
            result.finish(True)
            print(f"✓ Controller performance: {num_steps} steps in {result.duration_ms}ms")
            
        except Exception as e:
            result.finish(False, str(e))
            print(f"✗ Controller performance test failed: {e}")
        
        return result
    
    def run_memory_stress_test(self) -> TestResult:
        """Test memory usage under stress."""
        result = TestResult("Memory Stress")
        result.start()
        
        try:
            # Create many objects to test memory handling
            controllers = []
            
            for i in range(10):  # Create multiple controllers
                clock = MockClock()
                sensor = MockTemperatureSensor(clock)
                cool_actuator = MockActuator(f"COOL_{i}")
                heat_actuator = MockActuator(f"HEAT_{i}")
                
                controller = CoolOnlyController(
                    sensor=sensor,
                    cool_actuator=cool_actuator,
                    heat_actuator=heat_actuator,
                    clock=clock,
                    setpoint_tenths=230,
                    deadband_tenths=10,
                    min_on_ms=1000,
                    min_off_ms=1000
                )
                
                controllers.append(controller)
            
            # Run all controllers for many cycles
            for cycle in range(100):
                for i, controller in enumerate(controllers):
                    # Set different temperatures
                    temp = 200 + (i * 10) + (cycle % 20)
                    controller._sensor.set_temperature_c(temp / 10.0)
                    controller._clock.advance(100)
                    
                    status = controller.step()
                
                # Periodic garbage collection
                if cycle % 20 == 0:
                    gc.collect()
            
            result.finish(True)
            print(f"✓ Memory stress test completed in {result.duration_ms}ms, memory: {result.memory_used} bytes")
            
        except Exception as e:
            result.finish(False, str(e))
            print(f"✗ Memory stress test failed: {e}")
        
        return result
    
    def run_timing_precision_test(self) -> TestResult:
        """Test timing precision and accuracy."""
        result = TestResult("Timing Precision")
        result.start()
        
        try:
            clock = MockClock()
            
            # Test various time intervals
            test_intervals = [10, 50, 100, 500, 1000, 5000]
            
            for interval_ms in test_intervals:
                start_time = clock.now_ms()
                clock.advance(interval_ms)
                elapsed = clock.elapsed_ms(start_time)
                
                if elapsed != interval_ms:
                    raise AssertionError(f"Timing error: expected {interval_ms}ms, got {elapsed}ms")
            
            # Test timing under load
            for i in range(1000):
                start = clock.now_ms()
                clock.advance(1)
                elapsed = clock.elapsed_ms(start)
                if elapsed != 1:
                    raise AssertionError(f"Timing error under load at iteration {i}")
            
            result.finish(True)
            print(f"✓ Timing precision test passed in {result.duration_ms}ms")
            
        except Exception as e:
            result.finish(False, str(e))
            print(f"✗ Timing precision test failed: {e}")
        
        return result
    
    def run_all_performance_tests(self) -> List[TestResult]:
        """Run all performance tests."""
        print("\nRunning Performance Tests...")
        print("-" * 30)
        
        tests = [
            self.run_controller_performance_test,
            self.run_memory_stress_test,
            self.run_timing_precision_test
        ]
        
        results = []
        for test in tests:
            result = test()
            results.append(result)
        
        return results

class TestSuite:
    """Main test suite orchestrator."""
    
    def __init__(self):
        self.unit_test_results: List[TestResult] = []
        self.performance_results: List[TestResult] = []
        self.total_start_time = 0
        self.total_duration_ms = 0
    
    def run_unit_tests(self) -> bool:
        """Run all unit tests."""
        print("BAS Controller Test Suite")
        print("=" * 50)
        
        all_passed = True
        
        # Test individual modules
        test_modules = [
            ("Controller V2", run_controller_tests),
            ("Services", run_all_services_tests)
        ]
        
        for module_name, test_func in test_modules:
            result = TestResult(module_name)
            result.start()
            
            try:
                print(f"\n{module_name} Tests:")
                test_func()
                result.finish(True)
                print(f"✓ {module_name} tests completed in {result.duration_ms}ms")
                
            except Exception as e:
                result.finish(False, str(e))
                print(f"✗ {module_name} tests failed: {e}")
                all_passed = False
            
            self.unit_test_results.append(result)
        
        return all_passed
    
    def run_performance_tests(self) -> bool:
        """Run performance tests."""
        perf_tester = PerformanceTest()
        self.performance_results = perf_tester.run_all_performance_tests()
        
        # Check if all performance tests passed
        return all(result.passed for result in self.performance_results)
    
    def run_integration_tests(self) -> bool:
        """Run integration tests."""
        print("\nRunning Integration Tests...")
        print("-" * 30)
        
        result = TestResult("Integration")
        result.start()
        
        try:
            # Test complete system integration
            clock = MockClock()
            sensor = MockTemperatureSensor(clock, initial_temp_tenths=230)
            cool_actuator = MockActuator("COOL")
            heat_actuator = MockActuator("HEAT")
            
            controller = CoolOnlyController(
                sensor=sensor,
                cool_actuator=cool_actuator,
                heat_actuator=heat_actuator,
                clock=clock,
                setpoint_tenths=230,
                deadband_tenths=10,
                min_on_ms=5000,
                min_off_ms=5000
            )
            
            # Simulate complete operation cycle
            simulation_steps = [
                # (time_advance_ms, temperature_c, expected_cooling_state, description)
                (0, 23.0, False, "Initial state - at setpoint"),
                (1000, 24.5, True, "High temp - start cooling"),
                (3000, 24.0, True, "Temp dropping but min_on not reached"),
                (3000, 22.5, False, "Low temp and min_on elapsed - stop cooling"),
                (2000, 24.5, False, "High temp but min_off not reached"),
                (4000, 24.5, True, "High temp and min_off elapsed - restart cooling"),
            ]
            
            for step_ms, temp_c, expected_cooling, description in simulation_steps:
                clock.advance(step_ms)
                sensor.set_temperature_c(temp_c)
                
                status = controller.step()
                
                if status.cool_active != expected_cooling:
                    raise AssertionError(f"Integration test failed: {description}")
                
                print(f"✓ {description}")
            
            result.finish(True)
            print(f"✓ Integration tests completed in {result.duration_ms}ms")
            return True
            
        except Exception as e:
            result.finish(False, str(e))
            print(f"✗ Integration tests failed: {e}")
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.unit_test_results) + len(self.performance_results)
        passed_tests = sum(1 for r in self.unit_test_results + self.performance_results if r.passed)
        
        unit_duration = sum(r.duration_ms for r in self.unit_test_results)
        perf_duration = sum(r.duration_ms for r in self.performance_results)
        
        total_memory = sum(r.memory_used for r in self.unit_test_results + self.performance_results)
        
        report = {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": total_tests - passed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "total_duration_ms": self.total_duration_ms,
                "unit_test_duration_ms": unit_duration,
                "performance_test_duration_ms": perf_duration,
                "total_memory_used": total_memory
            },
            "unit_test_results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "duration_ms": r.duration_ms,
                    "memory_used": r.memory_used,
                    "error": r.error_message
                }
                for r in self.unit_test_results
            ],
            "performance_results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "duration_ms": r.duration_ms,
                    "memory_used": r.memory_used,
                    "error": r.error_message
                }
                for r in self.performance_results
            ]
        }
        
        return report
    
    def run_all_tests(self) -> bool:
        """Run complete test suite."""
        self.total_start_time = time.ticks_ms()
        
        try:
            # Run unit tests
            unit_passed = self.run_unit_tests()
            
            # Run integration tests
            integration_passed = self.run_integration_tests()
            
            # Run performance tests
            perf_passed = self.run_performance_tests()
            
            self.total_duration_ms = time.ticks_diff(time.ticks_ms(), self.total_start_time)
            
            # Generate and display report
            report = self.generate_report()
            self.print_summary_report(report)
            
            return unit_passed and integration_passed and perf_passed
            
        except Exception as e:
            print(f"Test suite execution failed: {e}")
            return False
    
    def print_summary_report(self, report: Dict[str, Any]) -> None:
        """Print summary test report."""
        summary = report["summary"]
        
        print("\n" + "=" * 50)
        print("TEST SUITE SUMMARY REPORT")
        print("=" * 50)
        print(f"Total Tests:     {summary['total_tests']}")
        print(f"Passed:          {summary['passed_tests']}")
        print(f"Failed:          {summary['failed_tests']}")
        print(f"Success Rate:    {summary['success_rate']:.1f}%")
        print(f"Total Duration:  {summary['total_duration_ms']}ms")
        print(f"Memory Used:     {summary['total_memory_used']} bytes")
        
        # Show failed tests
        failed_tests = [r for r in self.unit_test_results + self.performance_results if not r.passed]
        if failed_tests:
            print("\nFAILED TESTS:")
            for test in failed_tests:
                print(f"  ✗ {test.name}: {test.error_message}")
        
        if summary['failed_tests'] == 0:
            print("\n🎉 ALL TESTS PASSED! 🎉")
        else:
            print(f"\n⚠️  {summary['failed_tests']} TESTS FAILED")
        
        print("=" * 50)

def main():
    """Main test runner entry point."""
    suite = TestSuite()
    
    # Set logging to minimal for tests
    LoggerFactory.set_print_enabled(False)
    
    success = suite.run_all_tests()
    
    # Exit with appropriate code
    if not success:
        print("Tests failed - see report above")
        return 1
    return 0

if __name__ == "__main__":
    exit_code = main()
    # In MicroPython, we can't use sys.exit(), so just print the result
    print(f"Test suite exit code: {exit_code}")
