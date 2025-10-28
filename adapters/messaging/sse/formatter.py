"""Internal SSE frame formatter."""
import json
from typing import Any, Optional


def _format_sse(data: Any, event: Optional[str] = None, id_value: Optional[str] = None) -> str:
	"""Return an SSE frame string. Internal helper; not exported."""
	try:
		payload = data if isinstance(data, str) else json.dumps(data, separators=(",", ":"))
	except Exception:
		payload = json.dumps({"error": "serialization_failed"})
	lines = []
	if id_value is not None:
		lines.append(f"id: {id_value}")
	if event:
		lines.append(f"event: {event}")
	for line in payload.splitlines() or [""]:
		lines.append(f"data: {line}")
	lines.append("")
	return "\n".join(lines) + "\n"
