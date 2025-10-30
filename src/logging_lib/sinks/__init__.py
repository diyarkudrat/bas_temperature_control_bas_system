"""Sink implementations."""

from .stdout import StdoutSink
from .memory import InMemorySink

__all__ = ["StdoutSink", "InMemorySink"]


