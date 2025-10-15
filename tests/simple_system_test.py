# simple_system_test.py

# Read DS18B20 temperature, toggle FAN 3x (with interlock), then LED HEATER 3x (with interlock),
# and finally force/hold both relays OFF until Ctrl+C.

from machine import Pin
import onewire, ds18x20, time

# ===== CONFIG (adjust if needed) =====
PIN_DS18B20 = 4     # Your working DS18B20 DATA pin
PIN_FAN     = 15    # Relay IN1 -> Fan
PIN_HEATER  = 14    # Relay IN2 -> LED heater
ACTIVE_LOW  = False # << CHANGED: your board behaves active-HIGH (HIGH=ON). Set True if LOW=ON.
CYCLES      = 3
DELAY_SEC   = 3.0
# ====================================

# Logic levels derived from polarity
OFF = 1 if ACTIVE_LOW else 0   # output level that turns relay OFF
ON  = 0 if ACTIVE_LOW else 1   # output level that turns relay ON

# Initialize relays to OFF
fan    = Pin(PIN_FAN,    Pin.OUT, value=OFF)
heater = Pin(PIN_HEATER, Pin.OUT, value=OFF)

def relay_on(pin):  pin.value(ON)
def relay_off(pin): pin.value(OFF)

# DS18B20 setup
ow = onewire.OneWire(Pin(PIN_DS18B20))
ds = ds18x20.DS18X20(ow)
roms = ds.scan()

def read_temp():
    ds.convert_temp()
    time.sleep_ms(750)
    t_c = ds.read_temp(roms[0])
    t_f = t_c * 9/5 + 32
    return t_c, t_f

def toggle_with_interlock(target_pin, target_name, other_pin, other_name, cycles, delay):
    # Hard interlock: ensure the other output is OFF before any action
    relay_off(other_pin)
    time.sleep_ms(50)

    print(f"\n🔹 Toggling {target_name} {cycles} times (interlocked):")
    for i in range(cycles):
        print(f"{target_name} ON ({i+1}/{cycles})")
        relay_on(target_pin)
        relay_off(other_pin)   # keep other OFF during ON window
        time.sleep(delay)

        print(f"{target_name} OFF ({i+1}/{cycles})")
        relay_off(target_pin)
        relay_off(other_pin)   # both OFF between pulses
        time.sleep(delay)

    # Post-condition: target OFF, other OFF
    relay_off(target_pin)
    relay_off(other_pin)
    print(f"{target_name} test complete. ({target_name}=OFF, {other_name}=OFF)")

try:
    if not roms:
        print("❌ No DS18B20 detected on GP", PIN_DS18B20)
    else:
        print(f"✅ Found {len(roms)} sensor(s): {[r.hex() for r in roms]}\n")
        t_c, t_f = read_temp()
        print(f"🌡️  Current temperature: {t_c:.2f}°C / {t_f:.2f}°F")

    # 1) Fan test (forces heater OFF while fan is exercised)
    toggle_with_interlock(fan, "Fan", heater, "LED Heater", CYCLES, DELAY_SEC)

    # 2) LED heater test (forces fan OFF while heater is exercised)
    toggle_with_interlock(heater, "LED Heater", fan, "Fan", CYCLES, DELAY_SEC)

finally:
    # Sticky OFF cleanup: force OFF, then hold pins in OFF level
    relay_off(fan)
    relay_off(heater)
    time.sleep_ms(50)

    if ACTIVE_LOW:
        fan    = Pin(PIN_FAN,    Pin.IN, Pin.PULL_UP)    # HIGH holds OFF for active-LOW boards
        heater = Pin(PIN_HEATER, Pin.IN, Pin.PULL_UP)
    else:
        fan    = Pin(PIN_FAN,    Pin.IN, Pin.PULL_DOWN)  # LOW holds OFF for active-HIGH boards
        heater = Pin(PIN_HEATER, Pin.IN, Pin.PULL_DOWN)

    print("\n✅ Test complete — relays forced OFF and held OFF.")
    print("ℹ️  Leave this running; press Ctrl+C to release and exit.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Re-drive OFF on graceful exit (belt & suspenders)
        Pin(PIN_FAN,    Pin.OUT, value=OFF)
        Pin(PIN_HEATER, Pin.OUT, value=OFF)
        print("\nRelays OFF. Exiting.")
