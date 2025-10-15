# netctrl/wifi.py

import network, time

def connect_wifi(ssid, password, timeout_s=30, max_retries=3):
    """Connect to WiFi with timeout, status updates, and retry logic."""
    print(f"WiFi: Connecting to '{ssid}'...")
    
    sta = network.WLAN(network.STA_IF)
    
    # Check if already connected
    if sta.active() and sta.isconnected():
        ip = sta.ifconfig()[0]
        print(f"WiFi: Already connected to {ip}")
        return ip
    
    # Try multiple times (some routers reject rapid reconnects)
    for attempt in range(max_retries):
        if attempt > 0:
            print(f"WiFi: Retry attempt {attempt + 1}/{max_retries}...")
            time.sleep_ms(2000)  # Wait before retry
        
        # Reset adapter completely
        if sta.active():
            print("WiFi: Resetting adapter...")
            sta.disconnect()
            sta.active(False)
            time.sleep_ms(1000)
        
        # Activate adapter fresh
        print("WiFi: Activating adapter...")
        sta.active(True)
        time.sleep_ms(1000)
        
        # Connect
        print(f"WiFi: Initiating connection...")
        sta.connect(ssid, password)
    
        t0 = time.ticks_ms()
        dots = 0
        last_status = None
        failed_this_attempt = False
        
        while not sta.isconnected():
            elapsed_s = time.ticks_diff(time.ticks_ms(), t0) // 1000
            current_status = sta.status()
            
            # Show progress with status changes
            if elapsed_s > dots or current_status != last_status:
                status_msgs = {
                    0: "Link down",
                    1: "Joining...",
                    2: "No IP",
                    3: "Connected",
                    -1: "Failed",
                    -2: "Network not found",
                    -3: "Auth failed"
                }
                status_msg = status_msgs.get(current_status, f"Status {current_status}")
                print(f"WiFi: {status_msg} ({elapsed_s}s)")
                dots = elapsed_s
                last_status = current_status
                
                # Check for errors (but don't give up yet - might be transient)
                if current_status < 0:
                    failed_this_attempt = True
                    break  # Exit this attempt, will retry
            
            time.sleep_ms(500)
            
            # Timeout for this attempt
            if time.ticks_diff(time.ticks_ms(), t0) > timeout_s * 1000:
                print(f"WiFi: Attempt timed out (Status: {current_status})")
                failed_this_attempt = True
                break
        
        # Check if connected
        if sta.isconnected():
            ip = sta.ifconfig()[0]
            print(f"WiFi: Connected! IP: {ip}")
            return ip
        
        # If not connected and this was the last attempt, fail
        if not sta.isconnected() and attempt == max_retries - 1:
            final_status = sta.status()
            if final_status == -3:
                raise RuntimeError("WiFi: Authentication failed after all retries")
            elif final_status == -2:
                raise RuntimeError("WiFi: Network not found")
            else:
                raise RuntimeError(f"WiFi: Connection failed (status: {final_status})")
    
    # Shouldn't reach here, but just in case
    raise RuntimeError("WiFi: Connection failed after all retries")
