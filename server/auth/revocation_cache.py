from __future__ import annotations

import threading
import time
from typing import Callable, Optional


class RevocationCache:
    """In-process revocation cache with TTL and optional pubsub invalidation.

    Backend: a callable is_revoked(token_id) -> bool (e.g., RevocationService.is_revoked).
    """

    def __init__(self, is_revoked_backend: Callable[[str], bool], ttl_s: float = 5.0) -> None:
        self._backend = is_revoked_backend
        self._ttl = float(ttl_s)
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[bool, float]] = {}
        self._stop = threading.Event()
        self._subscriber_thread: Optional[threading.Thread] = None
        self._pubsub = None

    @property
    def backend(self) -> Callable[[str], bool]:
        return self._backend

    def get(self, token_id: str) -> bool:
        now = time.time()
        with self._lock:
            item = self._cache.get(token_id)
            if item is not None:
                value, ts = item
                if (now - ts) <= self._ttl:
                    return value
                # expired
                del self._cache[token_id]
        # Cache miss or expired: query backend outside lock
        value = False
        try:
            value = bool(self._backend(token_id))
        except Exception:
            value = False
        with self._lock:
            self._cache[token_id] = (value, now)
        return value

    def invalidate(self, token_id: str) -> None:
        with self._lock:
            if token_id in self._cache:
                del self._cache[token_id]

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    # Optional Redis pubsub integration (best-effort)
    def start_pubsub(self, redis_client, channel: str = "auth:revocations:invalidate") -> None:
        if redis_client is None or not channel or self._subscriber_thread is not None:
            return
        try:
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(channel)
            self._pubsub = pubsub
        except Exception:
            return

        def _loop():
            while not self._stop.is_set():
                try:
                    msg = self._pubsub.get_message(timeout=1.0)
                    if not msg:
                        continue
                    data = msg.get("data")
                    if isinstance(data, (bytes, bytearray)):
                        token_id = data.decode("utf-8", errors="ignore").strip()
                    else:
                        token_id = str(data).strip()
                    if token_id:
                        self.invalidate(token_id)
                except Exception:
                    # Sleep briefly to avoid hot loop on errors
                    time.sleep(0.25)

        self._subscriber_thread = threading.Thread(target=_loop, name="revocation-cache-sub", daemon=True)
        self._subscriber_thread.start()

    def stop_pubsub(self) -> None:
        self._stop.set()
        try:
            if self._pubsub is not None:
                self._pubsub.close()
        except Exception:
            pass

