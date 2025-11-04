"""Tests for structured logging context propagation and reset."""

from __future__ import annotations

from logging_lib.logger import clear_context, get_context, logger_context, pop_context, push_context


def test_logger_context_scopes_state_per_request(memory_logger, memory_sink) -> None:
    """Context manager should attach and remove request metadata per invocation."""

    with logger_context(request_id="req-1", tenant="acme"):
        assert get_context()["request_id"] == "req-1"
        memory_logger.info("within-context")

    memory_logger.info("outside-context")

    assert len(memory_sink.records) == 2
    first, second = memory_sink.records
    assert first["context"]["request_id"] == "req-1"
    assert first["context"]["tenant"] == "acme"
    assert "request_id" not in second["context"]
    assert "tenant" not in second["context"]
    assert get_context() == {}


def test_manual_context_tokens_can_be_cleared(memory_logger, memory_sink) -> None:
    """Manual push/pop of context tokens should be reversible without leaks."""

    token = push_context(trace_id="trace-123")
    memory_logger.info("with-token")
    pop_context(token)

    assert "trace_id" in memory_sink.records[-1]["context"]

    clear_context()
    assert get_context() == {}

    memory_logger.info("after-clear")
    assert "trace_id" not in memory_sink.records[-1]["context"]


