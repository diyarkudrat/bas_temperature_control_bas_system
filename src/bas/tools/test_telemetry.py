#!/usr/bin/env python3
"""
Test suite for BAS Controller telemetry endpoints.
Verifies that telemetry data is being collected and served correctly.
"""

import requests
import json
import time
from datetime import datetime
from typing import Optional

# Configuration - UPDATE THIS
PICO_IP = "192.168.1.XXX"  # Replace with your Pico W IP
BASE_URL = f"http://{PICO_IP}"
API_TOKEN = "change-this-token"  # From config/config.py


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'


def test_endpoint(name: str, url: str, method: str = 'GET', data: Optional[dict] = None) -> tuple[bool, dict]:
    """Test an API endpoint and return success status and response data."""
    try:
        if method == 'GET':
            response = requests.get(url, timeout=5)
        else:
            response = requests.post(url, json=data, timeout=5)
        
        response.raise_for_status()
        return True, response.json()
    except requests.exceptions.Timeout:
        print(f"  {Colors.RED}✗ Timeout - check if Pico W is responding{Colors.END}")
        return False, {}
    except requests.exceptions.ConnectionError:
        print(f"  {Colors.RED}✗ Connection failed - check IP address and WiFi{Colors.END}")
        return False, {}
    except requests.exceptions.HTTPError as e:
        print(f"  {Colors.RED}✗ HTTP error: {e.response.status_code}{Colors.END}")
        return False, {}
    except json.JSONDecodeError:
        print(f"  {Colors.RED}✗ Invalid JSON response{Colors.END}")
        return False, {}
    except Exception as e:
        print(f"  {Colors.RED}✗ Error: {str(e)}{Colors.END}")
        return False, {}


def test_connectivity():
    """Test 1: Basic connectivity to Pico W."""
    print(f"\n{Colors.BOLD}1️⃣  Testing Connectivity{Colors.END}")
    print(f"   Target: {BASE_URL}")
    
    success, data = test_endpoint("connectivity", f"{BASE_URL}/status")
    if success:
        print(f"  {Colors.GREEN}✓ Pico W is reachable{Colors.END}")
        return True
    return False


def test_controller_status():
    """Test 2: Controller status endpoint."""
    print(f"\n{Colors.BOLD}2️⃣  Testing /status Endpoint{Colors.END}")
    
    success, data = test_endpoint("status", f"{BASE_URL}/status")
    if success:
        print(f"  {Colors.GREEN}✓ Status endpoint working{Colors.END}")
        temp = data.get('temp_tenths')
        print(f"  Temperature: {temp / 10:.1f}°C" if temp else "  Temperature: N/A")
        print(f"  Setpoint: {data.get('setpoint_tenths', 0) / 10:.1f}°C")
        print(f"  State: {data.get('state', 'UNKNOWN')}")
        print(f"  Cooling: {'ON' if data.get('cool_active') else 'OFF'}")
        print(f"  Heating: {'ON' if data.get('heat_active') else 'OFF'}")
        if data.get('alarm'):
            print(f"  {Colors.YELLOW}⚠️  ALARM ACTIVE{Colors.END}")
        return True
    return False


def test_telemetry_data():
    """Test 3: Telemetry data collection."""
    print(f"\n{Colors.BOLD}3️⃣  Testing /telemetry Endpoint{Colors.END}")
    
    # Test with 1 minute of data
    success, data = test_endpoint("telemetry", f"{BASE_URL}/telemetry?duration_ms=60000&max_points=30")
    if success:
        point_count = data.get('count', 0)
        temperatures = data.get('temperatures', [])
        
        print(f"  {Colors.GREEN}✓ Telemetry endpoint working{Colors.END}")
        print(f"  Data points collected: {point_count}")
        print(f"  Duration requested: {data.get('duration_ms', 0) / 1000:.0f}s")
        
        # Analyze temperature data
        valid_temps = [t for t in temperatures if t is not None]
        if valid_temps:
            print(f"  Temperature range: {min(valid_temps):.1f}°C - {max(valid_temps):.1f}°C")
            print(f"  Valid readings: {len(valid_temps)}/{len(temperatures)}")
        else:
            print(f"  {Colors.YELLOW}⚠️  No valid temperature readings yet (system may be starting up){Colors.END}")
        
        # Check data freshness
        if data.get('timestamps'):
            latest_ts = max(data['timestamps'])
            age_ms = int(time.time() * 1000) - latest_ts
            print(f"  Latest data age: {age_ms / 1000:.1f}s")
            if age_ms > 10000:
                print(f"  {Colors.YELLOW}⚠️  Data may be stale{Colors.END}")
        
        return True
    return False


def test_telemetry_stats():
    """Test 4: Telemetry statistics."""
    print(f"\n{Colors.BOLD}4️⃣  Testing /telemetry/stats Endpoint{Colors.END}")
    
    # Test with 5 minutes of data
    success, data = test_endpoint("stats", f"{BASE_URL}/telemetry/stats?duration_ms=300000")
    if success:
        print(f"  {Colors.GREEN}✓ Stats endpoint working{Colors.END}")
        print(f"  Points analyzed: {data.get('point_count', 0)}")
        
        # Temperature statistics
        if 'temperature' in data and 'error' not in data['temperature']:
            temp = data['temperature']
            print(f"  Average temp: {temp.get('avg_c', 0):.1f}°C")
            print(f"  Min/Max: {temp.get('min_c', 0):.1f}°C / {temp.get('max_c', 0):.1f}°C")
            current = temp.get('current_c')
            print(f"  Current: {current:.1f}°C" if current else "  Current: N/A")
        else:
            print(f"  {Colors.YELLOW}⚠️  No temperature statistics available{Colors.END}")
        
        # Duty cycle statistics
        if 'duty_cycles' in data:
            duty = data['duty_cycles']
            print(f"  Cooling duty cycle: {duty.get('cooling_pct', 0):.1f}%")
            print(f"  Cooling cycles: {duty.get('cooling_cycles', 0)}")
            print(f"  Heating duty cycle: {duty.get('heating_pct', 0):.1f}%")
        
        # Alarm statistics
        alarm_pct = data.get('alarm_pct', 0)
        if alarm_pct > 0:
            print(f"  {Colors.YELLOW}⚠️  Alarms: {alarm_pct:.1f}% of time{Colors.END}")
        else:
            print(f"  Alarms: None")
        
        return True
    return False


def test_telemetry_health():
    """Test 5: Telemetry system health."""
    print(f"\n{Colors.BOLD}5️⃣  Testing /telemetry/health Endpoint{Colors.END}")
    
    success, data = test_endpoint("health", f"{BASE_URL}/telemetry/health")
    if success:
        print(f"  {Colors.GREEN}✓ Health endpoint working{Colors.END}")
        print(f"  Telemetry enabled: {data.get('enabled', False)}")
        print(f"  Total collections: {data.get('collection_count', 0)}")
        print(f"  Collection rate: {data.get('collection_rate_hz', 0):.2f} Hz")
        
        # Buffer statistics
        if 'buffer_stats' in data:
            buf = data['buffer_stats']
            size = buf.get('size', 0)
            capacity = buf.get('capacity', 0)
            utilization = buf.get('utilization_pct', 0)
            
            print(f"  Buffer: {size}/{capacity} points ({utilization:.1f}% full)")
            print(f"  Dropped points: {buf.get('dropped_points', 0)}")
            
            # Warnings
            if utilization > 90:
                print(f"  {Colors.YELLOW}⚠️  Buffer nearly full{Colors.END}")
            if buf.get('dropped_points', 0) > 100:
                print(f"  {Colors.YELLOW}ℹ️  Points dropped (normal for ring buffer after ~10min){Colors.END}")
        
        # CSV export status
        if data.get('csv_enabled'):
            print(f"  CSV export: Enabled ({data.get('csv_write_count', 0)} writes)")
        else:
            print(f"  CSV export: Disabled")
        
        return True
    return False


def test_continuous_collection():
    """Test 6: Continuous data collection over time."""
    print(f"\n{Colors.BOLD}6️⃣  Testing Continuous Collection{Colors.END}")
    print(f"  Collecting data over 10 seconds...")
    
    # Get initial count
    success1, data1 = test_endpoint("health1", f"{BASE_URL}/telemetry/health")
    if not success1:
        return False
    
    initial_count = data1.get('collection_count', 0)
    print(f"  Initial collection count: {initial_count}")
    
    # Wait 10 seconds
    time.sleep(10)
    
    # Get final count
    success2, data2 = test_endpoint("health2", f"{BASE_URL}/telemetry/health")
    if not success2:
        return False
    
    final_count = data2.get('collection_count', 0)
    new_collections = final_count - initial_count
    
    print(f"  Final collection count: {final_count}")
    print(f"  New collections: {new_collections}")
    
    # Expected: ~5 collections in 10s at 2s interval
    if new_collections >= 4:
        print(f"  {Colors.GREEN}✓ Telemetry actively collecting data{Colors.END}")
        return True
    elif new_collections > 0:
        print(f"  {Colors.YELLOW}⚠️  Collection rate lower than expected{Colors.END}")
        return True
    else:
        print(f"  {Colors.RED}✗ No new collections - telemetry may not be running{Colors.END}")
        return False


def main():
    """Run all telemetry tests."""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}🧪 BAS Controller Telemetry Test Suite{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"\nTesting Pico W at: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        test_connectivity,
        test_controller_status,
        test_telemetry_data,
        test_telemetry_stats,
        test_telemetry_health,
        test_continuous_collection,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"  {Colors.RED}✗ Test failed with exception: {str(e)}{Colors.END}")
            results.append(False)
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}📊 Test Summary{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"\nPassed: {passed}/{total} tests")
    
    if passed == total:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ All tests passed! Telemetry is working correctly.{Colors.END}")
        print(f"\n{Colors.BOLD}Next steps:{Colors.END}")
        print(f"  • View dashboard: {BASE_URL}/")
        print(f"  • Build React app: cd web-dashboard && npm install && npm run dev")
        print(f"  • Monitor logs: ./monitor")
        return 0
    elif passed > 0:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  Some tests failed. Check configuration and connectivity.{Colors.END}")
        return 1
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}✗ All tests failed. Check if Pico W is online and IP is correct.{Colors.END}")
        print(f"\n{Colors.BOLD}Troubleshooting:{Colors.END}")
        print(f"  1. Check IP address in this script (currently: {PICO_IP})")
        print(f"  2. Verify WiFi connection: ./monitor")
        print(f"  3. Check config/config.py has correct WiFi credentials")
        print(f"  4. Redeploy if needed: ./deploy")
        return 2


if __name__ == '__main__':
    try:
        exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Tests interrupted by user{Colors.END}")
        exit(130)

