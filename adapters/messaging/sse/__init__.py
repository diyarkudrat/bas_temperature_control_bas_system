"""Server-Sent Events (SSE) messaging adapter."""

# Adapters SSE package exports reusing server/services/sse_service structure
from .service import SSEService  # noqa: F401
from .factory import get_sse_service  # noqa: F401


