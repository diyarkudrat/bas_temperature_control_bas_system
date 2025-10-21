"""Factory for constructing SSEService with config defaults."""
from .service import SSEService


def get_sse_service(
	heartbeat_interval_s: float = 20.0,
	subscriber_queue_maxsize: int = 100,
) -> SSEService:
	"""
	Create a configured SSEService instance.
	Keep API surface minimal; callers should not depend on internals.
	"""
	return SSEService(
		heartbeat_interval_s=heartbeat_interval_s,
		subscriber_queue_maxsize=subscriber_queue_maxsize,
	)


