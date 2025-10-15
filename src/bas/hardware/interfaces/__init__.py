# interfaces/__init__.py
# Abstract interfaces for hardware abstraction layer

from .sensor import TemperatureSensor, SensorReading
from .actuator import Actuator
from .clock import Clock

__all__ = ['TemperatureSensor', 'SensorReading', 'Actuator', 'Clock']
