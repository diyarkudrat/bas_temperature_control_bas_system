"""Public SSEService facade over internal hub/backends."""
from typing import Optional, Any, Iterator
from .hub import _InProcessHub
from .redis_backend import _RedisBackend, _RedisPyClientAdapter


class SSEService:
	"""Public API used by routes; internals remain private."""

	def __init__(self, heartbeat_interval_s: float = 20.0, subscriber_queue_maxsize: int = 100) -> None:
		self._hub = _InProcessHub(heartbeat_interval_s, subscriber_queue_maxsize)
		self._redis = None  # placeholder for future backend

	def publish(self, data: Any, event: Optional[str] = None) -> int:
		frame = self._hub.next_frame(data, event=event)
		return self._hub.publish(frame)

	def subscribe(self, client_id: str) -> Iterator[bytes]:
		return self._hub.subscribe(client_id)

	def subscriber_count(self) -> int:
		return self._hub.subscriber_count()

	def attach_redis(self, *args, **kwargs) -> None:
		"""Attach a Redis backend using boundary-first client adapter.

		Constructor-injected via composition root; this method is a thin
		adapter to keep callsites stable during Phase 2. Accepts either a
		redis-py client via `client=...` or connection params via `url`.
		"""
		client = kwargs.get("client")
		url = kwargs.get("url")
		if client is None and url is None:
			return
		try:
			if client is None and url is not None:
				# Lazy import to avoid hard dependency at import time
				import redis  # type: ignore
				client = redis.Redis.from_url(url)
			adapter = _RedisPyClientAdapter(client)
			self._redis = _RedisBackend(adapter)
		except Exception:
			# Keep in-process hub if Redis cannot be attached
			self._redis = None


