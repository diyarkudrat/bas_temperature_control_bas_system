"""Factory for constructing SSEService with config defaults."""
import os
from .service import SSEService
from .breakers import CircuitBreaker
from .redis_backend import _RedisBackend, _RedisPyClientAdapter, _RedisConfig



def get_sse_service(
	heartbeat_interval_s: float = 20.0,
	subscriber_queue_maxsize: int = 100,
) -> SSEService:
	"""
	Create a configured SSEService instance.
	Keep API surface minimal; callers should not depend on internals.
	"""
	# Configure circuit breaker (env-tunable; defaults match Phase 3 plan)
	br_threshold = int(os.getenv("SSE_BREAKER_THRESHOLD", "5"))
	br_window_s = float(os.getenv("SSE_BREAKER_WINDOW_S", "30"))
	br_reset_s = float(os.getenv("SSE_BREAKER_RESET_S", "15"))
	breaker = CircuitBreaker(
		failure_threshold=br_threshold,
		window_s=br_window_s,
		reset_timeout_s=br_reset_s,
	)

	service = SSEService(
		heartbeat_interval_s=heartbeat_interval_s,
		subscriber_queue_maxsize=subscriber_queue_maxsize,
		breaker=breaker,
	)

	# Attach Redis backend when emulator mode is enabled and URL provided
	use_emulators = os.getenv("USE_EMULATORS", "0") in {"1", "true", "True"}
	redis_url = os.getenv("EMULATOR_REDIS_URL")
	if use_emulators and redis_url:
		try:
			# Boundary-first: construct redis client and configured backend
			import redis  # type: ignore

			client = redis.Redis.from_url(redis_url)
			adapter = _RedisPyClientAdapter(client)

			# Redis op budgets (env-tunable)
			op_timeout_ms = int(os.getenv("SSE_REDIS_OP_TIMEOUT_MS", "10"))
			max_retries = int(os.getenv("SSE_REDIS_MAX_RETRIES", "5"))
			channel_prefix = os.getenv("SSE_CHANNEL_PREFIX", "sse")

			cfg = _RedisConfig(
				url=redis_url,
				channel_prefix=channel_prefix,
				op_timeout_s=max(0.0, op_timeout_ms / 1000.0),
				max_retries=max(0, max_retries),
			)

			backend = _RedisBackend(adapter, config=cfg)
			# Recreate service injecting backend without altering breaker
			service = SSEService(
				heartbeat_interval_s=heartbeat_interval_s,
				subscriber_queue_maxsize=subscriber_queue_maxsize,
				breaker=breaker,
				redis_backend=backend,
			)
		except Exception:
			# Best-effort: keep in-process hub if Redis not available
			pass

	return service
