"""
SSE service public API.
Only expose high-level constructs; internals remain private.
"""

from .service import SSEService  # noqa: F401
from .factory import get_sse_service  # noqa: F401

__all__ = ["SSEService", "get_sse_service"]

__version__ = "0.1.0"

