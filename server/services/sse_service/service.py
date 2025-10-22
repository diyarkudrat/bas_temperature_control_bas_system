"""Public SSEService facade over internal hub/backends."""
from typing import Optional, Any, Iterator
from .hub import _InProcessHub
from .redis_backend import _RedisBackend, _RedisPyClientAdapter
from .breakers import CircuitBreaker

from flask import g as flask_g, has_request_context



class SSEService:
	"""Public API used by routes; internals remain private."""

	def __init__(self, heartbeat_interval_s: float = 20.0, subscriber_queue_maxsize: int = 100, *, breaker: Optional[CircuitBreaker] = None, redis_backend: Optional[_RedisBackend] = None) -> None:
		self._hub = _InProcessHub(heartbeat_interval_s, subscriber_queue_maxsize)
		self._redis = redis_backend  # optional injected backend
		self._redis_breaker = breaker or CircuitBreaker()

	def publish(self, data: Any, event: Optional[str] = None, *, tenant_id: Optional[str] = None, device_id: Optional[str] = None) -> int:
		"""Publish to in-process hub; mirror to Redis behind a breaker if attached.

		Returns number of local deliveries. Redis failures are isolated by breaker.
		"""
		# Best-effort fallback: if not provided, read from Flask context when available
		in_req_ctx = has_request_context()
		if tenant_id is None and in_req_ctx:
			tenant_id = getattr(flask_g, 'tenant_id', None)
		if device_id is None and in_req_ctx:
			device_id = getattr(flask_g, 'device_id', None)
			
		frame = self._hub.next_frame(data, event=event)
		local_deliveries = self._hub.publish(frame)
		# Attempt Redis fan-out with breaker guard; ignore result for caller
		self._publish_redis_mirrored(frame, tenant_id=tenant_id, device_id=device_id)
		return local_deliveries

	def _publish_redis_mirrored(self, frame: str, *, tenant_id: Optional[str] = None, device_id: Optional[str] = None) -> None:
		backend = self._redis
		if backend is None:
			return
		if not self._redis_breaker.allow_call():
			return
		# Publish as a simple envelope; backend serializer handles bytes
		success = False
		try:
			success = backend.publish("events", {"frame": frame}, tenant_id=tenant_id, device_id=device_id)
		finally:
			if success:
				self._redis_breaker.on_success()
			else:
				self._redis_breaker.on_failure()

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


