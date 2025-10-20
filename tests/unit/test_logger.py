from __future__ import annotations

import json
import logging
import time
from unittest.mock import patch

from server.services.logger import redact, AsyncSecureLogger, SecureLogRecord


def test_redact_masks_common_secrets():
    text = "password=abc123 token:dead auth_token=xyz authorization: Bearer abc.def"
    masked = redact(text)
    assert "REDACTED" in masked
    assert "abc123" not in masked and "xyz" not in masked and "abc.def" not in masked


def test_secure_log_record_to_json_handles_non_serializable():
    rec = SecureLogRecord(level="INFO", event="e", payload={"a": object()}, timestamp_ms=123)
    js = rec.to_json()
    data = json.loads(js)
    assert data["level"] == "INFO"
    assert data["event"] == "e"
    assert data["timestamp_ms"] == 123


def test_async_logger_sampling_and_queue(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    # Force should_log to always log
    logger = AsyncSecureLogger(max_queue=2, sample_rate=1.0, flush_interval_s=0.1)
    try:
        # Fill queue and trigger drop path
        for i in range(5):
            logger.log("INFO", "evt", {"s": f"password=val{i}"})
        # Allow flush loop to run
        time.sleep(0.2)
        # Stop worker to flush remaining
        logger.stop()
    finally:
        try:
            logger.stop()
        except Exception:
            pass

    # Some log lines should be present with redacted content
    found_payload = False
    for rec in caplog.records:
        if rec.levelno == logging.INFO and '"event": "evt"' in rec.msg:
            found_payload = True
            assert "REDACTED" in rec.msg
    assert found_payload


