#!/bin/bash
# wifi_debug.sh - Debug WiFi connection issues

DEVICE="${1:-/dev/cu.usbmodem114401}"

echo "🔍 WiFi Connection Diagnostics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "1️⃣ Checking WiFi credentials in config..."
mpremote connect "$DEVICE" exec "
from config.config import WIFI_SSID, WIFI_PASS
print(f'SSID: {WIFI_SSID}')
print(f'Password: {'*' * len(WIFI_PASS)} ({len(WIFI_PASS)} chars)')
"

echo ""
echo "2️⃣ Checking WiFi adapter status..."
mpremote connect "$DEVICE" exec "
import network
sta = network.WLAN(network.STA_IF)
print(f'Adapter active: {sta.active()}')
if sta.active():
    print(f'Connected: {sta.isconnected()}')
    if sta.isconnected():
        print(f'IP: {sta.ifconfig()[0]}')
        print(f'Gateway: {sta.ifconfig()[2]}')
    print(f'Status: {sta.status()}')
"

echo ""
echo "3️⃣ Scanning for available networks..."
mpremote connect "$DEVICE" exec "
import network
import time

sta = network.WLAN(network.STA_IF)
if not sta.active():
    sta.active(True)
    time.sleep(1)

print('Scanning...')
networks = sta.scan()
print(f'Found {len(networks)} networks:')

for net in networks[:10]:  # Show first 10
    ssid = net[0].decode('utf-8') if isinstance(net[0], bytes) else net[0]
    rssi = net[3]
    print(f'  - {ssid:30s} (Signal: {rssi} dBm)')
"

echo ""
echo "4️⃣ Attempting manual connection (30s timeout)..."
mpremote connect "$DEVICE" exec "
import network
import time
from config.config import WIFI_SSID, WIFI_PASS

sta = network.WLAN(network.STA_IF)

if not sta.active():
    print('Activating WiFi adapter...')
    sta.active(True)
    time.sleep(1)

if sta.isconnected():
    print(f'Already connected to: {sta.ifconfig()[0]}')
else:
    print(f'Connecting to {WIFI_SSID}...')
    sta.connect(WIFI_SSID, WIFI_PASS)
    
    t0 = time.ticks_ms()
    while not sta.isconnected():
        elapsed = time.ticks_diff(time.ticks_ms(), t0) // 1000
        if elapsed % 2 == 0:
            status = sta.status()
            print(f'  {elapsed}s - Status: {status}')
        
        time.sleep_ms(500)
        
        if time.ticks_diff(time.ticks_ms(), t0) > 30000:
            print(f'ERROR: Timeout after 30s')
            print(f'Final status: {sta.status()}')
            break
    
    if sta.isconnected():
        ip = sta.ifconfig()[0]
        print(f'SUCCESS! Connected to: {ip}')
    else:
        print('FAILED to connect')
        print('Status codes:')
        print('  0 = Link down')
        print('  1 = Link join')
        print('  2 = Link no IP')
        print('  3 = Link up (connected)')
        print('  -1 = Link fail')
        print('  -2 = No AP found')
        print('  -3 = Wrong password')
"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Diagnostics complete"

