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

	def publish(
		self,
		kind: str,
		payload: Any,
		tenant_id: Optional[str] = None,
		device_id: Optional[str] = None,
	) -> bool:
		"""Publish a single message to the derived channel."""
		channel = self._namer.topic(kind, tenant_id=tenant_id, device_id=device_id)
		data = self._ser.serialize(payload)
		try:
			self._client.publish(channel, data)
			self._metrics.inc("sse.redis.publish", {"channel": kind})
			return True
		except Exception:
			self._metrics.inc("sse.redis.publish.error", {"channel": kind})
			return False

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


