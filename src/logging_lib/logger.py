"""Logging facade for structured records."""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from threading import RLock
from typing import Any, Dict, Mapping, MutableMapping

from .config import LoggingSettings, get_settings
from .dispatcher import Dispatcher
from .queue import LogQueue
from .redaction import apply_redaction
from .sampling import should_emit
from .schema import build_log_record
from .sinks.memory import InMemorySink
from .sinks.stdout import StdoutSink


ContextData = Mapping[str, Any]

_CONTEXT: ContextVar[Mapping[str, Any]] = ContextVar("logging_lib_context", default={})


class StructuredLogger:
    """A structured logger that can be used to log messages."""

    def __init__(self, name: str, manager: "LoggerManager") -> None:
        """Initialize the logger with a given name and manager."""

        self._name = name
        self._manager = manager

    def debug(self, message: str, **fields: Any) -> None:
        """Log a debug message."""

        self._log("DEBUG", message, **fields)

    def info(self, message: str, **fields: Any) -> None:
        """Log an info message."""

        self._log("INFO", message, **fields)

    def warning(self, message: str, **fields: Any) -> None:
        """Log a warning message."""

        self._log("WARNING", message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        """Log an error message."""

        self._log("ERROR", message, **fields)

    def critical(self, message: str, **fields: Any) -> None:
        """Log a critical message."""

        self._log("CRITICAL", message, **fields)

    def _log(self, level: str, message: str, **fields: Any) -> None:
        """Log a message at a given level."""

        manager = self._manager
        settings = manager.settings

        if not should_emit(level, settings, _CONTEXT.get()):
            return

        base_context = manager.base_context

        runtime_context = dict(base_context)
        runtime_context.update(_CONTEXT.get())

        explicit_context = fields.pop("context", {}) or {}
        if explicit_context:
            runtime_context.update(explicit_context)

        runtime_context.setdefault("component", self._name)

        record = build_log_record(
            level=level,
            message=message,
            settings=settings,
            component=self._name,
            context=runtime_context,
            **fields,
        )
        sanitized = apply_redaction(record)

        manager.dispatcher.submit(sanitized)


class LoggerManager:
    """A manager for structured loggers."""

    def __init__(self) -> None:
        """Initialize the manager."""

        self._lock = RLock()
        self._loggers: Dict[str, StructuredLogger] = {}
        self._dispatcher: Dispatcher | None = None
        self._queue: LogQueue | None = None
        self._settings: LoggingSettings | None = None
        self._base_context: MutableMapping[str, Any] = {}

    def configure(self, settings: LoggingSettings) -> None:
        """Configure the manager with a given settings."""

        with self._lock:
            self._settings = settings
            self._loggers.clear()
            self._queue = LogQueue(settings.queue_size)
            self._dispatcher = Dispatcher(self._queue)
            sinks = [StdoutSink()]
            if any(sink == "memory" for sink in settings.sinks):
                sinks.append(InMemorySink())
            self._dispatcher.register_sinks(sinks)
            self._base_context = dict(settings.default_context)

    @property
    def dispatcher(self) -> Dispatcher:
        """Return the dispatcher."""

        dispatcher = self._dispatcher

        if dispatcher is None:
            self.configure(get_settings())
            dispatcher = self._dispatcher

        assert dispatcher is not None  # For type checkers

        return dispatcher

    @property
    def settings(self) -> LoggingSettings:
        """Return the settings."""

        settings = self._settings

        if settings is None:
            settings = get_settings()
            self.configure(settings)

        return settings

    @property
    def base_context(self) -> Mapping[str, Any]:
        """Return the base context."""

        return dict(self._base_context)

    def get_logger(self, name: str) -> StructuredLogger:
        """Return the logger with a given name."""

        with self._lock:
            logger = self._loggers.get(name)

            if logger is None:
                logger = StructuredLogger(name, self)
                self._loggers[name] = logger

            return logger

    def reset(self) -> None:
        """Reset the manager."""

        with self._lock:
            self._loggers.clear()
            self._queue = None
            self._dispatcher = None
            self._settings = None
            self._base_context.clear()


_MANAGER = LoggerManager()


def configure_manager(settings: LoggingSettings) -> None:
    """Configure the manager with a given settings."""

    _MANAGER.configure(settings)


def get_logger(name: str) -> StructuredLogger:
    """Return the logger with a given name."""

    return _MANAGER.get_logger(name)


@contextmanager
def logger_context(**context: Any):
    """Set the context for the logger."""

    current = dict(_CONTEXT.get())
    current.update(context)
    token = _CONTEXT.set(current)
    try:
        yield current
    finally:
        _CONTEXT.reset(token)


def reset_loggers() -> None:
    """Reset the loggers."""
    
    _MANAGER.reset()


def dump_memory_sink() -> str:
    """Return JSON representation of the memory sink contents (for debugging)."""

    dispatcher = _MANAGER.dispatcher
    for sink in getattr(dispatcher, "_sinks", []):
        if isinstance(sink, InMemorySink):
            return json.dumps(sink.records, indent=2)
    return "[]"


