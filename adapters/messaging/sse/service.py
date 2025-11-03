"""Public SSE service facade over internal hub/backends.

The service is used to publish messages to the in-process hub and mirror to Redis behind a breaker if attached.
"""

from typing import Optional, Any, Iterator

from flask import g as flask_g, has_request_context

from .hub import _InProcessHub
from .redis_backend import _RedisBackend, _RedisPyClientAdapter
from .breakers import CircuitBreaker


class SSEService:
    """Public API used by routes; internals remain private."""

    def __init__(
        self,
        heartbeat_interval_s: float = 20.0,
        subscriber_queue_maxsize: int = 100,
        *,
        breaker: Optional[CircuitBreaker] = None,
        redis_backend: Optional[_RedisBackend] = None,
    ) -> None:
        """Initialize the SSE service."""

        self._hub = _InProcessHub(heartbeat_interval_s, subscriber_queue_maxsize)
        self._redis_backend: Optional[_RedisBackend] = redis_backend
        self._redis_breaker = breaker or CircuitBreaker()

    @property
    def redis_backend(self) -> Optional[_RedisBackend]:
        """Return the currently attached Redis backend, if any."""

        return self._redis_backend

    @property
    def redis_breaker(self) -> CircuitBreaker:
        """Expose the breaker for observability/testing."""

        return self._redis_breaker

    def publish(
        self,
        data: Any,
        event: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> int:
        """Publish to in-process hub; mirror to Redis behind a breaker if attached."""

        tenant, device = self._resolve_context_ids(tenant_id=tenant_id, device_id=device_id)

        try:
            frame = self._hub.next_frame(data, event=event)
            local_deliveries = self._hub.publish(frame)
        except Exception:
            return 0

        self._publish_redis_mirrored(frame, tenant_id=tenant, device_id=device)

        return local_deliveries

    def subscribe(self, client_id: str) -> Iterator[bytes]:
        """Subscribe to the SSE service."""

        return self._hub.subscribe(client_id)

    def subscriber_count(self) -> int:
        """Get the number of subscribers."""
        
        return self._hub.subscriber_count()

    def attach_redis(self, *args, **kwargs) -> None:
        """Attach a Redis backend using boundary-first client adapter."""

        client = kwargs.get("client")
        url = kwargs.get("url")

        if client is None and url is None:
            return

        try:
            backend_client = client

            if backend_client is None and url is not None:
                try:
                    import redis  # type: ignore
                except Exception:
                    return

                backend_client = redis.Redis.from_url(url)

            if backend_client is None:
                return

            adapter = _RedisPyClientAdapter(backend_client)
            self._redis_backend = _RedisBackend(adapter)
        except Exception:
            self._redis_backend = None

    def _resolve_context_ids(
        self,
        *,
        tenant_id: Optional[str],
        device_id: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """Resolve tenant/device identifiers from arguments or Flask context."""

        in_req_ctx = has_request_context()

        tenant = tenant_id if tenant_id is not None else (getattr(flask_g, "tenant_id", None) if in_req_ctx else None)
        device = device_id if device_id is not None else (getattr(flask_g, "device_id", None) if in_req_ctx else None)

        return tenant, device

    def _publish_redis_mirrored(
        self,
        frame: str,
        *,
        tenant_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> None:
        """Publish to Redis mirrored from in-process hub."""

        backend = self._redis_backend
        if backend is None:
            return

        if not self._redis_breaker.allow_call():
            return

        success = False
		
        try:
            success = backend.publish("events", {"frame": frame}, tenant_id=tenant_id, device_id=device_id)
        finally:
            if success:
                self._redis_breaker.on_success()
            else:
                self._redis_breaker.on_failure()
