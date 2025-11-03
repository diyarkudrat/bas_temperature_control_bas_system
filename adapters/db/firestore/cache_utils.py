"""Shared cache protocol and helpers for Firestore stores."""

from __future__ import annotations

from typing import Protocol, Optional, Union, Tuple, Dict, Any
import json


class CacheClient(Protocol):
	"""Cache client protocol."""

	def get(self, key: str) -> Optional[bytes]: ...
	def setex(self, key: str, ttl_seconds: int, value: str) -> None: ...
	def delete(self, key: str) -> None: ...
	def ttl(self, key: str) -> Optional[int]: ...



def cap_ttl_seconds(requested_ttl_s: int, max_ttl_s: int) -> int:
	"""Cap the TTL seconds."""
	return max(1, min(int(requested_ttl_s), int(max_ttl_s)))


def normalize_key_part(value: object) -> str:
	"""Normalize the key part."""
	return str(value).strip()


def ensure_text(value: Optional[Union[str, bytes, bytearray]]) -> Optional[str]:
	"""Ensure the text."""

	if value is None:
		return None

	if isinstance(value, str):
		return value

	try:
		return bytes(value).decode("utf-8")
	except Exception:
		return None



def json_dumps_compact(obj: Any) -> str:
	"""Compact JSON encoding for cache payloads."""
	return json.dumps(obj, separators=(",", ":"))



def json_loads_safe(s: Optional[str]) -> Optional[Any]:
	"""Load the JSON safely."""

	if not s:
		return None

	try:
		return json.loads(s)
	except Exception:
		return None
