from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

_LOG = logging.getLogger(__name__)

SECRET_PATTERNS = [
    re.compile(r"(auth[_-]?token|password|secret|api[_-]?key)\s*[:=]\s*([^\s,]+)", re.IGNORECASE),
    re.compile(r"(authorization)\s*[:=]\s*(Bearer\s+[^\s,]+)", re.IGNORECASE),
]


def redact(text: str) -> str:
    def _mask(m: re.Match[str]) -> str:
        key = m.group(1)
        return f"{key}=***REDACTED***"
    result = text
    for pat in SECRET_PATTERNS:
        result = pat.sub(_mask, result)
    return result


@dataclass
class SecureLogRecord:
    level: str
    event: str
    payload: Dict[str, Any]
    timestamp_ms: int

    def to_json(self) -> str:
        try:
            return json.dumps({
                "level": self.level,
                "event": self.event,
                "payload": self.payload,
                "timestamp_ms": self.timestamp_ms,
            }, ensure_ascii=False)
        except Exception:
            return json.dumps({
                "level": self.level,
                "event": self.event,
                "payload": str(self.payload),
                "timestamp_ms": self.timestamp_ms,
            }, ensure_ascii=False)


class AsyncSecureLogger:
    def __init__(self, max_queue: int = 10000, sample_rate: float = 1.0, flush_interval_s: float = 0.5):
        self._q: queue.Queue[SecureLogRecord] = queue.Queue(maxsize=max_queue)
        self._sample_rate = max(0.0, min(1.0, sample_rate))
        self._flush_interval_s = max(0.05, flush_interval_s)
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def _should_log(self) -> bool:
        if self._sample_rate >= 0.999:
            return True
        # Simple time-based sampler: log roughly sample_rate of events
        return (int(time.time() * 1000) % 1000) / 1000.0 < self._sample_rate

    def _run(self) -> None:
        last_flush = time.time()
        buf: list[SecureLogRecord] = []
        while not self._stop.is_set():
            try:
                try:
                    item = self._q.get(timeout=self._flush_interval_s)
                    buf.append(item)
                except queue.Empty:
                    pass
                now = time.time()
                if buf and (now - last_flush >= self._flush_interval_s):
                    for rec in buf:
                        _LOG.info(rec.to_json())
                    buf.clear()
                    last_flush = now
            except Exception as e:
                _LOG.warning("Async logger worker error: %s", e)

    def stop(self) -> None:
        self._stop.set()
        self._worker.join(timeout=1.0)

    def log(self, level: str, event: str, payload: Dict[str, Any]) -> None:
        if not self._should_log():
            return
        ts_ms = int(time.time() * 1000)
        safe_payload: Dict[str, Any] = {}
        for k, v in (payload or {}).items():
            try:
                if isinstance(v, str):
                    safe_payload[k] = redact(v)
                else:
                    safe_payload[k] = v
            except Exception:
                safe_payload[k] = str(v)
        rec = SecureLogRecord(level=level, event=event, payload=safe_payload, timestamp_ms=ts_ms)
        try:
            self._q.put_nowait(rec)
        except queue.Full:
            # Drop with a single warning per interval
            if self._should_log():
                _LOG.warning("Secure logger queue full; dropping event %s", event)

    def log_alert_attempt(self, channel: str, target: str, status: str, detail: Optional[str] = None) -> None:
        payload = {"channel": channel, "target": target, "status": status}
        if detail:
            payload["detail"] = detail
        self.log("INFO", "alert_attempt", payload)


