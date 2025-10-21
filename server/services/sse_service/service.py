"""Public SSEService facade over internal hub/backends."""
from typing import Optional, Any, Iterator
from .hub import _InProcessHub


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
		# Intentionally no-op until backend is provided
		pass


