"""Sink implementations for logging_lib."""

from .memory import InMemorySink
from .stdout import StdoutSink

__all__ = ["InMemorySink", "StdoutSink"]


