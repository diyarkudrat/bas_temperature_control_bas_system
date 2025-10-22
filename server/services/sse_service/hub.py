"""Internal in-process SSE hub with heartbeats."""
import time
import logging
import threading
from queue import Queue, Empty
from typing import Dict, Iterator
from .formatter import _format_sse

logger = logging.getLogger(__name__)


class _InProcessHub:
	"""Private fan-out hub; not part of public API."""

	def __init__(self, heartbeat_interval_s: float, subscriber_queue_maxsize: int) -> None:
		self._heartbeat_interval_s = heartbeat_interval_s
		self._subscriber_queue_maxsize = subscriber_queue_maxsize
		self._subscribers: Dict[str, Queue[str]] = {}
		self._subscribers_lock = threading.RLock()
		self._next_event_id = 0

	def _next_id(self) -> str:
		self._next_event_id += 1
		return str(self._next_event_id)

	def publish(self, frame: str) -> int:
		deliveries = 0
		dropped = 0
		with self._subscribers_lock:
			for sid, q in list(self._subscribers.items()):
				try:
					q.put_nowait(frame)
					deliveries += 1
				except Exception:
					dropped += 1
					try:
						del self._subscribers[sid]
					except Exception:
						pass
		if dropped:
			logger.warning("Dropped %s subscriber(s) due to slow consumer", dropped)
		return deliveries

	def subscribe(self, client_id: str) -> Iterator[bytes]:
		q: Queue[str] = Queue(maxsize=self._subscriber_queue_maxsize)
		with self._subscribers_lock:
			self._subscribers[client_id] = q
		logger.info("SSE subscriber added: %s (total=%d)", client_id, len(self._subscribers))

		last_send = time.monotonic()
		try:
			while True:
				now = time.monotonic()
				if now - last_send >= self._heartbeat_interval_s:
					# Use wall clock for payload timestamp while using monotonic for scheduling
					hb = _format_sse({"ts": int(time.time() * 1000)}, event="heartbeat", id_value=self._next_id())
					try:
						yield hb.encode("utf-8")
					except Exception:
						# placeholder for metrics
						pass
					last_send = now
				try:
					frame = q.get(timeout=0.5)
					last_send = time.monotonic()
					try:
						yield frame.encode("utf-8")
					except Exception:
						# placeholder for metrics
						pass
				except Empty:
					continue
		except GeneratorExit:
			pass
		except Exception as e:
			logger.warning("SSE stream error for %s: %s", client_id, e)
		finally:
			with self._subscribers_lock:
				self._subscribers.pop(client_id, None)
			logger.info("SSE subscriber removed: %s (total=%d)", client_id, len(self._subscribers))

	def next_frame(self, data, event=None) -> str:
		"""Helper to format with next id."""
		return _format_sse(data, event=event, id_value=self._next_id())

	def subscriber_count(self) -> int:
		with self._subscribers_lock:
			return len(self._subscribers)


