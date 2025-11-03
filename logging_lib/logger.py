"""Structured logging facade."""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar, Token
from threading import RLock
from typing import Any, Dict, Mapping, MutableMapping, Optional

from .config import LoggingSettings, get_settings
from .dispatcher import Dispatcher
from .metrics import reset_metrics
from .queue import RingBufferQueue
from .redaction import RedactorRegistry, build_registry
from .sampling import should_emit
from .schema import build_log_record
from .sinks.memory import InMemorySink
from .sinks.stdout import StdoutSink

try:  # Optional dependency present in production
    from .sinks.gcl_api import GoogleCloudLoggingSink  # type: ignore
except Exception:  # pragma: no cover - optional
    GoogleCloudLoggingSink = None


_CONTEXT: ContextVar[Mapping[str, Any]] = ContextVar("logging_lib_context", default={})


class StructuredLogger:
    """Structured logger for the logging library."""

    def __init__(self, name: str, manager: "LoggerManager") -> None:
        """Initialize the structured logger with a given name and manager."""

        self._name = name # The name of the logger
        self._manager = manager # The manager for the logger

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

        context_snapshot = _CONTEXT.get()

        if not should_emit(level, settings, context_snapshot):
            return

        runtime_context = dict(manager.base_context)
        runtime_context.update(context_snapshot)

        explicit_context = fields.pop("context", {}) or {}
        if explicit_context:
            runtime_context.update(explicit_context)

        record = build_log_record(
            level=level,
            message=message,
            settings=settings,
            component=self._name,
            context=runtime_context,
            **fields,
        )
        redactor = manager.redactor
        sanitized = redactor.apply(record) if redactor else record

        manager.dispatcher.submit(sanitized)


class LoggerManager:
    """Manager for the structured loggers."""

    def __init__(self) -> None:
        """Initialize the logger manager."""

        self._lock = RLock() # The lock for the logger manager
        self._loggers: Dict[str, StructuredLogger] = {} # The loggers
        self._settings: LoggingSettings | None = None # The settings for the logger manager
        self._dispatcher: Dispatcher | None = None # The dispatcher for the logger manager
        self._queue: RingBufferQueue | None = None # The queue for the logger manager
        self._base_context: MutableMapping[str, Any] = {} # The base context for the logger manager
        self._redactor: Optional[RedactorRegistry] = None

    def configure(self, settings: LoggingSettings) -> None:
        """Configure the logger manager with a given settings."""

        with self._lock:
            self._shutdown_dispatcher()

            self._settings = settings
            self._loggers.clear()

            self._queue = RingBufferQueue(
                settings.queue_size, on_drop=self._handle_drop
            )
            sinks = []

            for sink_name in settings.sinks:
                name = sink_name.strip().lower()

                if name == "stdout":
                    sinks.append(StdoutSink(settings))

                elif name == "memory":
                    sinks.append(InMemorySink())

                elif name == "gcl":
                    if settings.gcl_enabled and GoogleCloudLoggingSink is not None:
                        sinks.append(
                            GoogleCloudLoggingSink(
                                project=settings.gcl_project,
                                log_name=settings.gcl_log_name,
                                service=settings.service,
                                env=settings.env,
                            )
                        )

            if not sinks:
                sinks.append(StdoutSink(settings))

            self._dispatcher = Dispatcher(
                self._queue,
                sinks,
                batch_size=settings.batch_size,
                flush_interval_ms=settings.flush_interval_ms,
                flush_timeout_ms=settings.flush_timeout_ms,
                worker_threads=settings.worker_threads,
                retry_initial_ms=settings.retry_initial_backoff_ms,
                retry_max_ms=settings.retry_max_backoff_ms,
            )

            self._base_context = dict(settings.default_context)
            self._redactor = build_registry(settings.redaction)

            reset_metrics()

    @property
    def dispatcher(self) -> Dispatcher:
        """Get the dispatcher for the logger manager."""

        dispatcher = self._dispatcher

        if dispatcher is None:
            self.configure(get_settings())
            dispatcher = self._dispatcher

        assert dispatcher is not None

        return dispatcher

    @property
    def settings(self) -> LoggingSettings:
        """Get the settings for the logger manager."""

        settings = self._settings

        if settings is None:
            settings = get_settings()
            self.configure(settings)

        return settings

    @property
    def base_context(self) -> Mapping[str, Any]:
        """Get the base context for the logger manager."""

        return dict(self._base_context)

    @property
    def redactor(self) -> Optional[RedactorRegistry]:
        return self._redactor

    def get_logger(self, name: str) -> StructuredLogger:
        """Get a logger with a given name."""

        with self._lock:
            logger = self._loggers.get(name)

            if logger is None:
                logger = StructuredLogger(name, self)
                self._loggers[name] = logger

            return logger

    def reset(self) -> None:
        """Reset the logger manager."""

        with self._lock:
            self._shutdown_dispatcher()
            self._loggers.clear()

            self._settings = None
            self._queue = None

            self._base_context.clear()
            self._redactor = None

    # --------------------- internal helpers ---------------------
    def _shutdown_dispatcher(self) -> None:
        """Shutdown the dispatcher for the logger manager."""

        dispatcher = self._dispatcher

        if dispatcher is not None:
            dispatcher.stop()

        self._dispatcher = None

    def _handle_drop(self, dropped: Mapping[str, object]) -> None:
        dispatcher = self._dispatcher
        queue = self._queue
        settings = self._settings

        if dispatcher is None or queue is None or settings is None:
            return

        drop_metadata = queue.emit_drop_event(dropped)
        notice_context = dict(self._base_context)
        notice_context.update({"drop": drop_metadata})

        notice = build_log_record(
            level="WARNING",
            message="log_drop",
            settings=settings,
            component="logging.queue",
            context=notice_context,
        )

        redactor = self._redactor
        sanitized = redactor.apply(notice) if redactor else notice

        dispatcher.emit_immediate(sanitized)


_MANAGER = LoggerManager()


def configure_manager(settings: LoggingSettings) -> None:
    """Configure the manager with a given settings."""

    _MANAGER.configure(settings)


def get_logger(name: str) -> StructuredLogger:
    """Get a logger with a given name."""

    return _MANAGER.get_logger(name)


@contextmanager
def logger_context(**context: Any):
    """Context manager for temporary context variables."""

    token = push_context(**context)
    try:
        yield
    finally:
        pop_context(token)


def reset_loggers() -> None:
    """Reset the logger manager."""

    _MANAGER.reset()


def dump_memory_sink() -> str:
    """Dump the memory sink for the logger manager."""
    
    dispatcher = _MANAGER._dispatcher

    if dispatcher is None:
        return "[]"

    for sink in getattr(dispatcher, "_sinks", []):
        if hasattr(sink, "records"):
            return json.dumps(sink.records, indent=2)
            
    return "[]"


def push_context(**context: Any) -> Token:
    current = dict(_CONTEXT.get())
    current.update(context)
    return _CONTEXT.set(current)


def pop_context(token: Token) -> None:
    _CONTEXT.reset(token)


def get_context() -> Mapping[str, Any]:
    return dict(_CONTEXT.get())


def clear_context() -> None:
    _CONTEXT.set({})


