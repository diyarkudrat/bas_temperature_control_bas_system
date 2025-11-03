# pico_client.py - Minimal Pico W client for BAS system
# This client only handles hardware and communicates with the computer server

import json
import time
import socket
from machine import Pin
import onewire, ds18x20
import network

# Configuration
SERVER_URL = "http://192.168.1.131:8080"  # Change to your computer's IP
WIFI_SSID = "SpectrumSetup-3581"
WIFI_PASSWORD = "chancesinger785"

# Hardware pins
PIN_DS18B20 = 4
PIN_RELAY_COOL = 15
PIN_RELAY_HEAT = 14

class MinimalSensor:
    """Minimal DS18B20 sensor driver."""
    
    def __init__(self, pin_num):
        self._ow = onewire.OneWire(Pin(pin_num))
        self._ds = ds18x20.DS18X20(self._ow)
        
        # Find sensor
        roms = self._ds.scan()
        if not roms:
            raise RuntimeError("DS18B20 sensor not found")
        self._rom = roms[0]
    
    def read_temperature(self):
        """Read temperature in tenths of °C."""
        try:
            self._ds.convert_temp()
            time.sleep_ms(750)  # Wait for conversion
            temp_c = self._ds.read_temp(self._rom)
            
            if temp_c is None:
                return None, False
            
            # Convert to tenths of °C
            temp_tenths = int(round(temp_c * 10))
            
            # Sanity check
            if temp_tenths < -550 or temp_tenths > 1250:
                return None, False
            
            return temp_tenths, True
        except:
            return None, False

class MinimalRelay:
    """Minimal relay driver."""
    
    def __init__(self, pin_num, name):
        self.name = name
        self._pin = Pin(pin_num, Pin.OUT)
        self._pin.value(0)  # Start OFF
        self._state = False
    
    def set_state(self, active):
        """Set relay state (True = ON, False = OFF)."""
        self._pin.value(1 if active else 0)
        self._state = active
    
    def get_state(self):
        """Get current relay state."""
        return self._state

class MinimalClient:
    """Minimal Pico W client for BAS system."""
    
    def __init__(self):
        self.sensor = None
        self.cool_relay = None
        self.heat_relay = None
        self.wifi = None
        self.ip_address = None
        self.server_ip = None
        self.server_port = 8080
        
        # Parse server URL
        self._parse_server_url()
    
    def _parse_server_url(self):
        """Parse SERVER_URL to extract IP and port."""
        # Remove http:// prefix
        url = SERVER_URL.replace("http://", "")
        
        # Split by colon to get IP and port
        if ":" in url:
            self.server_ip, port_str = url.split(":", 1)
            self.server_port = int(port_str)
        else:
            self.server_ip = url
            self.server_port = 80  # Default HTTP port
    
    def initialize_hardware(self):
        """Initialize hardware components."""
        print("Initializing hardware...")
        
        try:
            # Initialize sensor
            self.sensor = MinimalSensor(PIN_DS18B20)
            print("✓ DS18B20 sensor initialized")
            
            # Initialize relays
            self.cool_relay = MinimalRelay(PIN_RELAY_COOL, "cooling")
            self.heat_relay = MinimalRelay(PIN_RELAY_HEAT, "heating")
            print("✓ Relays initialized")
            
            return True
        except Exception as e:
            print(f"✗ Hardware initialization failed: {e}")
            return False
    
    def connect_wifi(self):
        """Connect to WiFi network."""
        print(f"Connecting to WiFi: {WIFI_SSID}")
        
        self.wifi = network.WLAN(network.STA_IF)
        self.wifi.active(True)
        self.wifi.connect(WIFI_SSID, WIFI_PASSWORD)
        
        # Wait for connection
        timeout = 30
        start_time = time.ticks_ms()
        
        while not self.wifi.isconnected():
            if time.ticks_diff(time.ticks_ms(), start_time) > timeout * 1000:
                print("✗ WiFi connection timeout")
                return False
            time.sleep_ms(500)
        
        self.ip_address = self.wifi.ifconfig()[0]
        print(f"✓ WiFi connected: {self.ip_address}")
        return True
    
    def read_sensor_data(self):
        """Read sensor data."""
        temp_tenths, ok = self.sensor.read_temperature()
        
        return {
            "temp_tenths": temp_tenths,
            "sensor_ok": ok,
            "timestamp": time.ticks_ms()
        }
    
    def send_data_to_server(self, data):
        """Send sensor data to server."""
        try:
            # Create HTTP request
            json_data = json.dumps(data)
            request = (
                f"POST /api/sensor_data HTTP/1.1\r\n"
                f"Host: {self.server_ip}:{self.server_port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(json_data)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{json_data}"
            )
            
            # Send request
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.server_ip, self.server_port))
            sock.send(request.encode())
            
            # Read complete HTTP response
            response = ""
            headers_complete = False
            content_length = 0
            body_start = 0
            
            while True:
                try:
                    chunk = sock.recv(1024).decode()
                    if not chunk:
                        break
                    response += chunk
                    
                    # Parse headers to get content length
                    if not headers_complete and "\r\n\r\n" in response:
                        headers_complete = True
                        body_start = response.find("\r\n\r\n") + 4
                        
                        # Extract Content-Length header
                        content_length_line = ""
                        for line in response.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                content_length_line = line
                                break
                        
                        if content_length_line:
                            content_length = int(content_length_line.split(':')[1].strip())
                        
                        # Check if we have complete response
                        if content_length > 0:
                            expected_total = body_start + content_length
                            if len(response) >= expected_total:
                                break
                        else:
                            # No content length, break on connection close
                            if "Connection: close" in response:
                                break
                except:
                    break
            sock.close()
            
            # Debug: print response
            print(f"Server response: {response[:200]}...")
            
            # Parse response for control commands
            if "200 OK" in response:
                # Extract JSON from response body
                try:
                    if body_start > 0:
                        body = response[body_start:body_start + content_length]
                        print(f"Response body: {body}")
                        if body.strip():
                            commands = json.loads(body)
                            print(f"Parsed commands: {commands}")
                            return commands
                        else:
                            print("Warning: Empty response body")
                            print(f"Full response length: {len(response)}")
                            print(f"Body start: {body_start}, Content-Length: {content_length}")
                    else:
                        print("Warning: No response body found")
                except json.JSONDecodeError as parse_error:
                    print(f"JSON parse error: {parse_error}")
                    print(f"Raw body: '{body}'")
                    print(f"Body length: {len(body)}")
                except Exception as parse_error:
                    print(f"Unexpected parse error: {parse_error}")
                    pass
            else:
                print(f"Non-200 response: {response[:100]}...")
            
            return {}
            
        except Exception as e:
            print(f"✗ Failed to send data to server: {e}")
            return {}
    
    def execute_control_commands(self, commands):
        """Execute control commands from server."""
        if not commands:
            return
        
        try:
            if "cool_active" in commands:
                self.cool_relay.set_state(commands["cool_active"])
                print(f"Cooling relay: {'ON' if commands['cool_active'] else 'OFF'}")
            
            if "heat_active" in commands:
                self.heat_relay.set_state(commands["heat_active"])
                print(f"Heating relay: {'ON' if commands['heat_active'] else 'OFF'}")
                
        except Exception as e:
            print(f"✗ Failed to execute commands: {e}")
    
    def run(self):
        """Main client loop."""
        print("Starting BAS Pico W client...")
        
        # Initialize hardware
        if not self.initialize_hardware():
            return
        
        # Connect to WiFi
        if not self.connect_wifi():
            return
        
        print("✓ Client ready! Starting main loop...")
        
        # Main loop
        loop_count = 0
        while True:
            try:
                # Read sensor data
                sensor_data = self.read_sensor_data()
                
                # Send data to server and get control commands
                commands = self.send_data_to_server(sensor_data)
                
                # Execute control commands
                self.execute_control_commands(commands)
                
                # Status update every 10 loops
                loop_count += 1
                if loop_count % 10 == 0:
                    temp_c = sensor_data["temp_tenths"] / 10 if sensor_data["temp_tenths"] else 0
                    print(f"Loop {loop_count}: Temp={temp_c:.1f}°C, "
                          f"Cool={'ON' if self.cool_relay.get_state() else 'OFF'}, "
                          f"Heat={'ON' if self.heat_relay.get_state() else 'OFF'}")
                
                # Wait before next iteration
                time.sleep(2)  # 2 second loop
                
            except KeyboardInterrupt:
                print("\nShutting down...")
                break
            except Exception as e:
                print(f"✗ Loop error: {e}")
                time.sleep(5)  # Wait before retry
    
    def cleanup(self):
        """Cleanup resources."""
        if self.cool_relay:
            self.cool_relay.set_state(False)
        if self.heat_relay:
            self.heat_relay.set_state(False)
        
        if self.wifi:
            self.wifi.disconnect()
        
        print("✓ Cleanup complete")

def main():
    """Main entry point."""
    client = MinimalClient()
    
    try:
        client.run()
    finally:
        client.cleanup()

if __name__ == "__main__":
    main()
