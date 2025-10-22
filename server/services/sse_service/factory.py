"""Factory for constructing SSEService with config defaults."""
import os
from .service import SSEService


def get_sse_service(
	heartbeat_interval_s: float = 20.0,
	subscriber_queue_maxsize: int = 100,
) -> SSEService:
	"""
	Create a configured SSEService instance.
	Keep API surface minimal; callers should not depend on internals.
	"""
	service = SSEService(
		heartbeat_interval_s=heartbeat_interval_s,
		subscriber_queue_maxsize=subscriber_queue_maxsize,
	)

	# Attach Redis backend when emulator mode is enabled and URL provided
	use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
	redis_url = os.getenv("EMULATOR_REDIS_URL")
	if use_emulators and redis_url:
		try:
			service.attach_redis(url=redis_url)
		except Exception:
			# Best-effort: keep in-process hub if Redis not available
			pass

	return service


