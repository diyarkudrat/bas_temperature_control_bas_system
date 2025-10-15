#!/usr/bin/env python3
# test_api.py - Test the BAS controller API

import requests
import json
import sys

# Configuration
PICO_IP = "192.168.1.129"  # Update this with your Pico's IP
API_TOKEN = "testapitoken"
BASE_URL = f"http://{PICO_IP}"

def test_get_status():
    """Test GET /status endpoint."""
    print("🔍 Testing GET /status...")
    try:
        response = requests.get(f"{BASE_URL}/status", timeout=5)
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Temperature: {data.get('temp_tenths', 0)/10:.1f}°C")
            print(f"   ✅ Setpoint: {data.get('setpoint_tenths', 0)/10:.1f}°C")
            print(f"   ✅ State: {data.get('state')}")
            print(f"   ✅ Cooling: {'ON' if data.get('cool_active') else 'OFF'}")
            print(f"   ✅ Sensor OK: {data.get('sensor_ok')}")
            return data
        else:
            print(f"   ❌ Request failed: {response.text}")
            return None
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return None

def test_set_setpoint(new_setpoint_c):
    """Test POST /set endpoint to change setpoint."""
    print(f"\n🔧 Testing POST /set (setpoint={new_setpoint_c}°C)...")
    try:
        # Convert Celsius to tenths
        setpoint_tenths = int(new_setpoint_c * 10)
        
        payload = {"sp": setpoint_tenths}
        response = requests.post(
            f"{BASE_URL}/set?token={API_TOKEN}",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=5
        )
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Response: {data}")
            return True
        else:
            print(f"   ❌ Request failed: {response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_invalid_token():
    """Test authentication with invalid token."""
    print("\n🔒 Testing authentication (invalid token)...")
    try:
        response = requests.post(
            f"{BASE_URL}/set?token=wrong_token",
            headers={"Content-Type": "application/json"},
            json={"sp": 250},
            timeout=5
        )
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 403:
            print("   ✅ Authentication correctly rejected invalid token")
            return True
        else:
            print(f"   ❌ Expected 403, got {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_config_endpoint():
    """Test GET /config endpoint."""
    print("\n⚙️  Testing GET /config...")
    try:
        response = requests.get(f"{BASE_URL}/config", timeout=5)
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Profile: {data.get('profile_name')}")
            print(f"   ✅ Setpoint: {data.get('setpoint_c')}°C")
            print(f"   ✅ Available profiles: {data.get('available_profiles')}")
            return data
        else:
            print(f"   ❌ Request failed: {response.text}")
            return None
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return None

def main():
    """Run all API tests."""
    print("=" * 60)
    print("BAS Controller API Test Suite")
    print(f"Target: {BASE_URL}")
    print("=" * 60)
    
    # Test 1: Get initial status
    initial_status = test_get_status()
    if not initial_status:
        print("\n❌ Failed to connect to Pico. Check IP address and WiFi.")
        sys.exit(1)
    
    initial_setpoint = initial_status.get('setpoint_tenths', 0) / 10
    
    # Test 2: Update setpoint
    new_setpoint = 24.0  # Change to 24.0°C
    if test_set_setpoint(new_setpoint):
        print(f"   ✅ Setpoint changed from {initial_setpoint}°C to {new_setpoint}°C")
    
    # Test 3: Verify change
    print("\n🔍 Verifying setpoint change...")
    updated_status = test_get_status()
    if updated_status:
        actual_setpoint = updated_status.get('setpoint_tenths', 0) / 10
        if abs(actual_setpoint - new_setpoint) < 0.1:
            print(f"   ✅ Setpoint verified: {actual_setpoint}°C")
        else:
            print(f"   ❌ Setpoint mismatch: expected {new_setpoint}°C, got {actual_setpoint}°C")
    
    # Test 4: Change it back
    if test_set_setpoint(initial_setpoint):
        print(f"   ✅ Setpoint restored to {initial_setpoint}°C")
    
    # Test 5: Test authentication
    test_invalid_token()
    
    # Test 6: Test config endpoint
    test_config_endpoint()
    
    print("\n" + "=" * 60)
    print("✅ API Test Suite Complete!")
    print("=" * 60)
    print(f"\n💡 View dashboard: {BASE_URL}/")
    print(f"💡 Watch live updates: curl {BASE_URL}/events")

if __name__ == "__main__":
    main()

