# core/__init__.py

from .relay import Relay
from .ds18b20 import DS18B20Sensor, TempReading, DS18B20ErrorCodes
from .clock import now_ms, elapsed_ms, SystemClock

# Export interfaces for convenience (v2 only - optional for v1 compatibility)
try:
    from interfaces import TemperatureSensor, SensorReading, Actuator, Clock
    _has_interfaces = True
except ImportError:
    _has_interfaces = False

if _has_interfaces:
    __all__ = [
        'Relay', 'DS18B20Sensor', 'TempReading', 'DS18B20ErrorCodes',
        'now_ms', 'elapsed_ms', 'SystemClock',
        'TemperatureSensor', 'SensorReading', 'Actuator', 'Clock'
    ]
else:
    __all__ = [
        'Relay', 'DS18B20Sensor', 'TempReading', 'DS18B20ErrorCodes',
        'now_ms', 'elapsed_ms', 'SystemClock'
    ]