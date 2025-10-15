# tests/test_telemetry.py
# Unit tests for telemetry system

import time
from services.telemetry import TelemetryPoint, TelemetryBuffer, TelemetryCollector
from controller import ControllerStatus

def test_telemetry_point_creation():
    """Test telemetry point creation and serialization."""
    print("Testing TelemetryPoint creation...")
    
    point = TelemetryPoint(
        timestamp_ms=1000,
        temp_tenths=235,
        setpoint_tenths=240,
        cool_active=True,
        heat_active=False,
        state="COOLING",
        alarm=False,
        error_code=0
    )
    
    assert point.timestamp_ms == 1000
    assert point.temp_tenths == 235
    assert point.cool_active == True
    
    # Test serialization
    data = point.to_dict()
    assert data['ts'] == 1000
    assert data['t'] == 235
    assert data['c'] == 1
    
    # Test deserialization
    point2 = TelemetryPoint.from_dict(data)
    assert point2.timestamp_ms == point.timestamp_ms
    assert point2.temp_tenths == point.temp_tenths
    
    print("✓ TelemetryPoint tests passed")
    return True

def test_telemetry_buffer():
    """Test ring buffer operations."""
    print("Testing TelemetryBuffer...")
    
    buffer = TelemetryBuffer(capacity=10)
    
    # Add some points
    for i in range(5):
        point = TelemetryPoint(
            timestamp_ms=i * 1000,
            temp_tenths=230 + i,
            setpoint_tenths=240,
            cool_active=False,
            heat_active=True,
            state="IDLE"
        )
        buffer.append(point)
    
    # Check size
    assert buffer._size == 5
    
    # Get recent points (should be newest first)
    recent = buffer.get_recent(count=3)
    assert len(recent) == 3
    assert recent[0].timestamp_ms == 4000  # Newest
    assert recent[2].timestamp_ms == 2000  # Oldest of the 3
    
    # Test overflow (add more than capacity)
    for i in range(5, 15):
        point = TelemetryPoint(
            timestamp_ms=i * 1000,
            temp_tenths=230 + i,
            setpoint_tenths=240,
            cool_active=False,
            heat_active=True,
            state="IDLE"
        )
        buffer.append(point)
    
    # Should have exactly capacity points
    assert buffer._size == 10
    assert buffer._dropped_points == 5  # 5 oldest points dropped
    
    # Get all chronological
    all_points = buffer.get_all_chronological()
    assert len(all_points) == 10
    assert all_points[0].timestamp_ms == 5000  # Oldest remaining
    assert all_points[-1].timestamp_ms == 14000  # Newest
    
    # Test clear
    buffer.clear()
    assert buffer._size == 0
    assert buffer.get_recent() == []
    
    print("✓ TelemetryBuffer tests passed")
    return True

def test_telemetry_collector():
    """Test telemetry collector with mock controller status."""
    print("Testing TelemetryCollector...")
    
    # Create collector (no CSV for tests)
    collector = TelemetryCollector(buffer_size=100, csv_path=None)
    
    # Simulate controller steps
    for i in range(20):
        status = ControllerStatus(
            state="COOLING" if i % 5 == 0 else "IDLE",
            temp_tenths=230 + (i % 10),
            setpoint_tenths=240,
            deadband_tenths=5,
            cool_active=(i % 5 == 0),
            heat_active=True,
            alarm=False,
            sensor_ok=True,
            error_code=0,
            age_ms=0
        )
        
        # Collect telemetry
        result = collector.collect(status)
        assert result == True
        
        # Small delay to vary timestamps
        time.sleep_ms(10)
    
    # Verify collection
    assert collector._collection_count == 20
    
    # Get time series
    data = collector.get_time_series_data(duration_ms=10000, max_points=50)
    assert 'timestamps' in data
    assert 'temperatures' in data
    assert len(data['temperatures']) == 20
    
    # Check temperature conversion (tenths to float)
    assert data['temperatures'][0] == 23.0  # 230 tenths = 23.0°C
    
    # Get statistics
    stats = collector.get_statistics(duration_ms=10000)
    assert 'temperature' in stats
    assert 'duty_cycles' in stats
    assert stats['point_count'] == 20
    
    # Check temperature stats
    temp_stats = stats['temperature']
    assert 'min_c' in temp_stats
    assert 'max_c' in temp_stats
    assert 'avg_c' in temp_stats
    
    # Get health metrics
    health = collector.get_system_health()
    assert health['enabled'] == True
    assert health['collection_count'] == 20
    
    print("✓ TelemetryCollector tests passed")
    return True

def test_telemetry_downsampling():
    """Test downsampling for large datasets."""
    print("Testing telemetry downsampling...")
    
    collector = TelemetryCollector(buffer_size=1000, csv_path=None)
    
    # Collect 500 points
    for i in range(500):
        status = ControllerStatus(
            state="IDLE",
            temp_tenths=230 + (i % 20),
            setpoint_tenths=240,
            deadband_tenths=5,
            cool_active=False,
            heat_active=True,
            alarm=False,
            sensor_ok=True,
            error_code=0,
            age_ms=0
        )
        collector.collect(status)
    
    # Request downsampled data (max 100 points from 500)
    data = collector.get_time_series_data(duration_ms=3600000, max_points=100)
    
    # Should be downsampled
    assert len(data['temperatures']) <= 100
    assert len(data['temperatures']) >= 95  # Allow some variance
    
    print(f"  Downsampled {collector._collection_count} points to {len(data['temperatures'])}")
    print("✓ Downsampling tests passed")
    return True

def test_telemetry_with_sensor_faults():
    """Test telemetry handles sensor faults gracefully."""
    print("Testing telemetry with sensor faults...")
    
    collector = TelemetryCollector(buffer_size=100, csv_path=None)
    
    # Collect mix of good and bad readings
    for i in range(10):
        status = ControllerStatus(
            state="FAULT" if i % 3 == 0 else "IDLE",
            temp_tenths=None if i % 3 == 0 else 230,  # Sensor fault
            setpoint_tenths=240,
            deadband_tenths=5,
            cool_active=False,
            heat_active=True,
            alarm=(i % 3 == 0),
            sensor_ok=(i % 3 != 0),
            error_code=102 if i % 3 == 0 else 0,
            age_ms=0
        )
        collector.collect(status)
    
    # Get statistics (should handle None temperatures)
    stats = collector.get_statistics(duration_ms=10000)
    
    # Should only count valid readings
    temp_stats = stats['temperature']
    assert 'avg_c' in temp_stats
    
    # Get time series (None should become null in JSON)
    data = collector.get_time_series_data(duration_ms=10000, max_points=50)
    none_count = sum(1 for t in data['temperatures'] if t is None)
    assert none_count > 0  # Should have some None values
    
    print(f"  Handled {none_count} sensor fault readings")
    print("✓ Sensor fault handling tests passed")
    return True

def run_all_tests():
    """Run all telemetry tests."""
    print("\n" + "="*60)
    print("TELEMETRY SYSTEM TESTS")
    print("="*60 + "\n")
    
    tests = [
        test_telemetry_point_creation,
        test_telemetry_buffer,
        test_telemetry_collector,
        test_telemetry_downsampling,
        test_telemetry_with_sensor_faults
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"✗ {test_func.__name__} failed")
        except Exception as e:
            failed += 1
            print(f"✗ {test_func.__name__} raised exception: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    if not success:
        import sys
        sys.exit(1)

