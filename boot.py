# boot.py (active-HIGH relays)
from machine import Pin
import time
Pin(15, Pin.IN, Pin.PULL_DOWN)
Pin(14, Pin.IN, Pin.PULL_DOWN)
time.sleep_ms(50)
Pin(15, Pin.OUT, value=0)   # LOW = OFF
Pin(14, Pin.OUT, value=0)
