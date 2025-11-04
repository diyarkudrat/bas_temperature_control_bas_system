"""Auth service client stub for unit tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AuthServiceResponse:
    access_token: str
    expires_in: int
    token_type: str = "Bearer"


class AuthServiceStub:
    """Minimal stub emulating the AuthServiceClient interface."""

    def __init__(self) -> None:
        """Initialize auth service stub."""

        self.requests: list[Dict[str, Any]] = []
        self.responses: list[AuthServiceResponse] = [
            AuthServiceResponse(access_token="stub-token", expires_in=60)
        ]

    def enqueue_response(self, response: AuthServiceResponse) -> None:
        """Enqueue a response."""

        self.responses.append(response)

    def fetch_token(self, *args: Any, **kwargs: Any) -> AuthServiceResponse:
        """Fetch a token."""

        payload = {"args": args, "kwargs": kwargs}
        self.requests.append(payload)

        if self.responses:
            return self.responses.pop(0)

        return AuthServiceResponse(access_token="default", expires_in=30)

    def reset(self) -> None:
        """Reset the auth service stub."""
        
        self.requests.clear()
        self.responses = [AuthServiceResponse(access_token="stub-token", expires_in=60)]

