"""Private Redis Pub/Sub adapter for SSE fan-out (internal only).

Design goals:
- Modular: pluggable serializer, channel naming, backoff, metrics, and client
- Safe defaults: no hard Redis import to avoid hard dependency at import time
- Encapsulation: not exported; callers interact via SSEService.attach_redis(...)
"""

from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass
from collections import deque
from typing import Any, Callable, Dict, Optional, Protocol


# ------------------------------
# Configuration (internal)
# ------------------------------

@dataclass
class _RedisConfig:
	"""Backend configuration."""
	url: Optional[str] = None
	channel_prefix: str = "sse"
	connect_timeout_s: float = 3.0
	read_timeout_s: float = 3.0
	# Soft per-op budget for hot-path ops (e.g., publish). This is a best-effort
	# budget and cannot preempt a blocking socket call.
	op_timeout_s: float = 0.01  # 10 ms target per publish
	pool_maxsize: int = 8
	max_retries: int = 5
	health_check_interval_s: float = 30.0


# ------------------------------
# Serializer (internal)
# ------------------------------

class _Serializer(Protocol):
	def serialize(self, obj: Any) -> bytes: ...
	def deserialize(self, data: bytes) -> Any: ...


class _JSONSerializer:
	"""Compact JSON serializer with stable separators."""
	def serialize(self, obj: Any) -> bytes:
		try:
			return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
		except Exception:
			# Last resort: wrap in error envelope
			return json.dumps({"error": "serialization_failed"}).encode("utf-8")

	def deserialize(self, data: bytes) -> Any:
		try:
			return json.loads(data.decode("utf-8"))
		except Exception:
			return {"error": "deserialization_failed"}


# ------------------------------
# Channel naming (internal)
# ------------------------------

class _ChannelNamer:
	"""Build hierarchical channels for multi-tenancy and device scope."""
	def __init__(self, prefix: str = "sse") -> None:
		self._prefix = prefix.rstrip(":")

	def topic(self, kind: str, tenant_id: Optional[str] = None, device_id: Optional[str] = None) -> str:
		parts = [self._prefix, kind]
		if tenant_id:
			parts.append(f"tenant:{tenant_id}")
		if device_id:
			parts.append(f"device:{device_id}")
		return ":".join(parts)


# ------------------------------
# Backoff policy (internal)
# ------------------------------

class _BackoffPolicy:
	"""Exponential backoff with jitter."""
	def __init__(self, base: float = 0.25, factor: float = 2.0, cap: float = 10.0) -> None:
		self._base = base
		self._factor = factor
		self._cap = cap

	def next_sleep(self, attempt: int) -> float:
		sleep = min(self._base * (self._factor ** max(0, attempt)), self._cap)
		# Full jitter
		return random.uniform(0, sleep)


# ------------------------------
# Metrics sink (internal)
# ------------------------------

class _MetricsSink:
	"""No-op metrics sink; replace with real sink as needed."""
	def inc(self, name: str, tags: Optional[Dict[str, str]] = None) -> None:
		pass

	def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
		pass


# ------------------------------
# Client protocol (internal)
# ------------------------------

class _RedisClient(Protocol):
	"""Thin protocol for a Redis client to enable easy swapping/mocking."""
	def publish(self, channel: str, message: bytes) -> int: ...
	def subscribe(self, channel: str) -> Any: ...
	def get_message(self, timeout: float = 0.0) -> Optional[Dict[str, Any]]: ...
	def unsubscribe(self, channel: str) -> None: ...
	def close(self) -> None: ...


# ------------------------------
# Backend facade (internal)
# ------------------------------

class _RedisBackend:
	"""
	Private Redis Pub/Sub facade used internally by SSEService.
	- Handles publish fan-out across processes
	- Manages a subscriber loop that forwards messages to a callback
	"""

	def __init__(
		self,
		client: _RedisClient,
		config: Optional[_RedisConfig] = None,
		serializer: Optional[_Serializer] = None,
		channel_namer: Optional[_ChannelNamer] = None,
		backoff: Optional[_BackoffPolicy] = None,
		metrics: Optional[_MetricsSink] = None,
	) -> None:
		self._client = client
		self._cfg = config or _RedisConfig()
		self._ser = serializer or _JSONSerializer()
		self._namer = channel_namer or _ChannelNamer(self._cfg.channel_prefix)
		self._backoff = backoff or _BackoffPolicy()
		self._metrics = metrics or _MetricsSink()

		self._stop = threading.Event()
		self._thread: Optional[threading.Thread] = None
		self._on_message: Optional[Callable[[Any], None]] = None
		self._subscribed_channel: Optional[str] = None

		# Local fallback queue for outage-resilient busting/replay.
		# Bounded to avoid unbounded memory use.
		self._fallback_max = 256
		self._fallback = deque(maxlen=self._fallback_max)
		self._fallback_lock = threading.Lock()
		self._fallback_enabled = True

	def _enqueue_fallback(self, channel: str, data: bytes) -> None:
		if not self._fallback_enabled:
			return
		try:
			with self._fallback_lock:
				self._fallback.append((channel, data))
			self._metrics.inc("sse.redis.fallback.enqueued", {"channel": channel})
		except Exception:
			pass

	def _flush_fallback(self, budget_s: float = 0.005) -> None:
		"""Best-effort flush of queued messages within a tiny time budget."""
		if not self._fallback_enabled:
			return
		start = time.monotonic()
		while True:
			if (time.monotonic() - start) >= budget_s:
				break
			item = None
			try:
				with self._fallback_lock:
					item = self._fallback.popleft() if self._fallback else None
			except Exception:
				item = None
			if not item:
				break
			channel, data = item
			try:
				self._client.publish(channel, data)
				self._metrics.inc("sse.redis.fallback.flushed", {"channel": channel})
			except Exception:
				# Push back if publish failed; stop flushing to avoid hot loop
				try:
					with self._fallback_lock:
						self._fallback.appendleft((channel, data))
				except Exception:
					pass
				break

	def publish(
		self,
		kind: str,
		payload: Any,
		tenant_id: Optional[str] = None,
		device_id: Optional[str] = None,
	) -> bool:
		"""Publish a single message to the derived channel with retries/backoff.

		Enforces a soft per-operation time budget (best effort) and retries with
		exponential backoff + jitter up to `max_retries`.
		"""
		channel = self._namer.topic(kind, tenant_id=tenant_id, device_id=device_id)
		data = self._ser.serialize(payload)
		start = time.monotonic()
		attempt = 0
		success = False
		# Opportunistically flush any queued messages first within a tiny budget
		self._flush_fallback(budget_s=0.001)
		while True:
			try:
				self._client.publish(channel, data)
				self._metrics.inc("sse.redis.publish", {"channel": kind})
				success = True
				# After a success, try to flush a bit more queued items if any budget remains
				elapsed = (time.monotonic() - start)
				remaining = max(0.0, self._cfg.op_timeout_s - elapsed)
				if remaining > 0:
					self._flush_fallback(budget_s=min(0.002, remaining))
				break
			except Exception:
				self._metrics.inc("sse.redis.publish.error", {"channel": kind})
				# Check soft time budget
				elapsed = (time.monotonic() - start)
				if elapsed >= self._cfg.op_timeout_s:
					# Enqueue for later replay
					self._enqueue_fallback(channel, data)
					break
				# If max retries reached, stop
				if attempt >= self._cfg.max_retries:
					self._enqueue_fallback(channel, data)
					break
				# Sleep with jittered backoff and retry
				sleep_s = self._backoff.next_sleep(attempt)
				# Clamp sleep to remaining budget
				remaining = max(0.0, self._cfg.op_timeout_s - elapsed)
				if sleep_s > remaining:
					sleep_s = remaining
				attempt = min(attempt + 1, self._cfg.max_retries)
				time.sleep(sleep_s)
		return success

	def start_subscriber(
		self,
		kind: str,
		on_message: Callable[[Any], None],
		tenant_id: Optional[str] = None,
		device_id: Optional[str] = None,
	) -> None:
		"""
		Start a background subscriber loop for the derived channel.
		Only one active subscription per backend instance is supported.
		"""
		if self._thread and self._thread.is_alive():
			return
		self._on_message = on_message
		self._subscribed_channel = self._namer.topic(kind, tenant_id=tenant_id, device_id=device_id)
		self._client.subscribe(self._subscribed_channel)
		self._stop.clear()
		self._thread = threading.Thread(target=self._reader_loop, name="sse-redis-reader", daemon=True)
		self._thread.start()

	def stop_subscriber(self) -> None:
		"""Stop background subscription and clean up."""
		self._stop.set()
		try:
			if self._subscribed_channel:
				self._client.unsubscribe(self._subscribed_channel)
		except Exception:
			pass
		if self._thread:
			self._thread.join(timeout=2.0)
		self._thread = None
		self._on_message = None
		self._subscribed_channel = None

	def _reader_loop(self) -> None:
		"""Receive and dispatch messages with resilient backoff."""
		attempt = 0
		while not self._stop.is_set():
			try:
				msg = self._client.get_message(timeout=self._cfg.read_timeout_s)
				if not msg:
					continue
				# Expect {'type': 'message', 'data': bytes, 'channel': str}
				data = msg.get("data")
				if isinstance(data, (bytes, bytearray)):
					payload = self._ser.deserialize(data)
				else:
					payload = data
				if self._on_message:
					self._on_message(payload)
				self._metrics.inc("sse.redis.message")
				attempt = 0  # reset after success
			except Exception:
				self._metrics.inc("sse.redis.reader.error")
				# Backoff before next poll to avoid hot loop on errors
				sleep_s = self._backoff.next_sleep(attempt)
				attempt = min(attempt + 1, self._cfg.max_retries)
				time.sleep(sleep_s)

	def close(self) -> None:
		"""Close backend and client."""
		self.stop_subscriber()
		try:
			self._client.close()
		except Exception:
			pass


# ------------------------------
# redis-py adapter (internal)
# ------------------------------

class _RedisPyClientAdapter:
    """
    Adapter around redis-py to match the minimal _RedisClient protocol.
    Boundary-first: narrow surface for publishing and simple subscription
    with polling via pubsub.get_message.
    """

    def __init__(self, redis_client: "Any") -> None:
        self._client = redis_client
        self._pubsub = None

    def publish(self, channel: str, message: bytes) -> int:
        return int(self._client.publish(channel, message) or 0)

    def subscribe(self, channel: str) -> Any:
        # Lazily create pubsub; ensure single subscription context
        if self._pubsub is None:
            self._pubsub = self._client.pubsub()
        self._pubsub.subscribe(channel)
        return self._pubsub

    def get_message(self, timeout: float = 0.0) -> Optional[Dict[str, Any]]:
        if self._pubsub is None:
            return None
        # redis-py expects timeout in seconds via blocking get_message
        msg = self._pubsub.get_message(timeout=timeout)
        return msg  # Already a dict or None

    def unsubscribe(self, channel: str) -> None:
        if self._pubsub is not None:
            try:
                self._pubsub.unsubscribe(channel)
            except Exception:
                pass

    def close(self) -> None:
        try:
            if self._pubsub is not None:
                try:
                    self._pubsub.close()
                except Exception:
                    pass
                self._pubsub = None
        finally:
            try:
                self._client.close()
            except Exception:
                pass
