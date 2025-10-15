#!/bin/bash
# Test script for BAS Controller telemetry endpoints

# Configuration - UPDATE THIS with your Pico W IP
PICO_IP="192.168.1.XXX"  # Replace with actual IP from monitor output
API_TOKEN="change-this-token"  # From config/config.py

echo "🧪 BAS Controller Telemetry Test Suite"
echo "========================================"
echo ""
echo "Testing Pico W at: http://$PICO_IP"
echo ""

# Test 1: Basic connectivity
echo "1️⃣  Testing connectivity..."
if curl -s --connect-timeout 3 "http://$PICO_IP/status" > /dev/null; then
    echo "✅ Pico W is reachable"
else
    echo "❌ Cannot connect to Pico W. Check IP address and WiFi."
    echo "   Current IP: $PICO_IP"
    echo "   Tip: Check ./monitor output for actual IP"
    exit 1
fi
echo ""

# Test 2: Controller status
echo "2️⃣  Testing /status endpoint..."
STATUS=$(curl -s "http://$PICO_IP/status")
if [ $? -eq 0 ]; then
    echo "✅ Status endpoint working"
    echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"
else
    echo "❌ Status endpoint failed"
fi
echo ""

# Test 3: Telemetry data
echo "3️⃣  Testing /telemetry endpoint..."
TELEMETRY=$(curl -s "http://$PICO_IP/telemetry?duration_ms=60000&max_points=30")
if [ $? -eq 0 ]; then
    echo "✅ Telemetry endpoint working"
    # Show first few data points
    echo "$TELEMETRY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  Points collected: {data.get('count', 0)}\")
print(f\"  Duration: {data.get('duration_ms', 0)/1000:.0f}s\")
if data.get('temperatures'):
    temps = [t for t in data['temperatures'] if t is not None]
    if temps:
        print(f\"  Temp range: {min(temps):.1f}°C - {max(temps):.1f}°C\")
    else:
        print('  ⚠️  No valid temperature readings yet')
" 2>/dev/null || echo "  (Raw data received, install Python to parse)"
else
    echo "❌ Telemetry endpoint failed"
fi
echo ""

# Test 4: Telemetry statistics
echo "4️⃣  Testing /telemetry/stats endpoint..."
STATS=$(curl -s "http://$PICO_IP/telemetry/stats?duration_ms=300000")
if [ $? -eq 0 ]; then
    echo "✅ Stats endpoint working"
    echo "$STATS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  Points analyzed: {data.get('point_count', 0)}\")
if 'temperature' in data and 'error' not in data['temperature']:
    temp = data['temperature']
    print(f\"  Avg temp: {temp.get('avg_c', 0):.1f}°C\")
    print(f\"  Min/Max: {temp.get('min_c', 0):.1f}°C / {temp.get('max_c', 0):.1f}°C\")
if 'duty_cycles' in data:
    duty = data['duty_cycles']
    print(f\"  Cooling duty: {duty.get('cooling_pct', 0):.1f}%\")
    print(f\"  Cooling cycles: {duty.get('cooling_cycles', 0)}\")
" 2>/dev/null || echo "  (Raw data received)"
else
    echo "❌ Stats endpoint failed"
fi
echo ""

# Test 5: Telemetry health
echo "5️⃣  Testing /telemetry/health endpoint..."
HEALTH=$(curl -s "http://$PICO_IP/telemetry/health")
if [ $? -eq 0 ]; then
    echo "✅ Health endpoint working"
    echo "$HEALTH" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  Enabled: {data.get('enabled', False)}\")
print(f\"  Collections: {data.get('collection_count', 0)}\")
print(f\"  Collection rate: {data.get('collection_rate_hz', 0):.2f} Hz\")
if 'buffer_stats' in data:
    buf = data['buffer_stats']
    print(f\"  Buffer: {buf.get('size', 0)}/{buf.get('capacity', 0)} ({buf.get('utilization_pct', 0):.1f}%)\")
    print(f\"  Dropped points: {buf.get('dropped_points', 0)}\")
" 2>/dev/null || echo "  (Raw data received)"
else
    echo "❌ Health endpoint failed"
fi
echo ""

# Test 6: Setpoint update (optional)
echo "6️⃣  Testing /set endpoint (optional - skipped)"
echo "   To test: curl -X POST \"http://$PICO_IP/set?token=$API_TOKEN\" \\"
echo "            -H \"Content-Type: application/json\" \\"
echo "            -d '{\"sp\": 250}'"
echo ""

# Summary
echo "========================================"
echo "✅ Testing complete!"
echo ""
echo "Next steps:"
echo "  - View dashboard: http://$PICO_IP/"
echo "  - View raw telemetry: http://$PICO_IP/telemetry"
echo "  - Monitor logs: ./monitor"
echo ""

