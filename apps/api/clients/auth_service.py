"""Client for delegating auth operations to the standalone auth service.

The client keeps all network side effects encapsulated so API handlers can
continue working with pure domain models.  Construct an instance per
application (or per request in tests) to avoid module-level state.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any, Mapping, MutableMapping, Optional

try:  # pragma: no cover - stdlib availability validated at runtime
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:  # pragma: no cover
    Request = None  # type: ignore
    urlopen = None  # type: ignore
    HTTPError = Exception  # type: ignore
    URLError = Exception  # type: ignore

from app_platform.security import ServiceTokenParams, build_auth_headers, sign_service_token


_JSON_HEADERS = {"Accept": "application/json"}


@dataclass(slots=True)
class AuthServiceResponse:
    """Normalized response returned by the auth service client."""

    status_code: int
    json: Optional[Mapping[str, Any]]
    headers: Mapping[str, str]
    cookies: Mapping[str, str]
    set_cookies: tuple[str, ...]
    raw_body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


@dataclass(slots=True)
class AuthServiceClientConfig:
    """Configuration for :class:`AuthServiceClient`."""

    base_url: str
    timeout_seconds: float = 5.0
    audience: str = "bas-auth"
    issuer: str = "bas-api"
    subject: str = "api-backend"
    token_secret: Optional[str] = None
    token_scope: Optional[str] = None
    static_token: Optional[str] = None
    token_ttl_seconds: int = 30
    forward_remote_addr_header: Optional[str] = "X-Forwarded-For"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AuthServiceClientConfig":
        """Load configuration from environment variables."""

        env = env or os.environ
        base_url = env.get("AUTH_SERVICE_URL", "http://localhost:9090").strip()
        timeout = float(env.get("AUTH_SERVICE_TIMEOUT_S", "5.0"))
        token_secret = env.get("AUTH_SERVICE_SIGNING_KEY") or None
        static_token = env.get("AUTH_SERVICE_SHARED_TOKEN") or None
        audience = env.get("AUTH_SERVICE_TOKEN_AUDIENCE", "bas-auth")
        issuer = env.get("AUTH_SERVICE_TOKEN_ISSUER", "bas-api")
        subject = env.get("AUTH_SERVICE_TOKEN_SUBJECT", "api-backend")
        scope = env.get("AUTH_SERVICE_TOKEN_SCOPE") or None
        ttl = int(env.get("AUTH_SERVICE_TOKEN_TTL_S", "30"))
        header_name = env.get("AUTH_SERVICE_REMOTE_ADDR_HEADER", "X-Forwarded-For") or None
        return cls(
            base_url=base_url,
            timeout_seconds=timeout,
            audience=audience,
            issuer=issuer,
            subject=subject,
            token_secret=token_secret,
            token_scope=scope,
            static_token=static_token,
            token_ttl_seconds=ttl,
            forward_remote_addr_header=header_name,
        )


class AuthServiceClient:
    """HTTP client that proxies auth actions to the standalone auth service."""

    def __init__(
        self,
        config: AuthServiceClientConfig,
        *,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the AuthServiceClient."""

        if Request is None or urlopen is None:  # pragma: no cover
            raise RuntimeError("urllib.request is required for AuthServiceClient")

        self._cfg = config
        self._base_url = config.base_url.rstrip("/")
        self._timeout = max(0.1, float(config.timeout_seconds))
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------ Public API ------------------------
    def login(
        self,
        username: str,
        password: str,
        *,
        tenant_id: Optional[str] = None,
        remote_addr: Optional[str] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Login to the auth service."""

        payload = {"username": username, "password": password}
        headers: MutableMapping[str, str] = {}
        if tenant_id:
            headers["X-BAS-Tenant"] = tenant_id
        if remote_addr and self._cfg.forward_remote_addr_header:
            headers[self._cfg.forward_remote_addr_header] = remote_addr
        if extra_headers:
            headers.update(extra_headers)
        return self._request("POST", "/auth/login", json_body=payload, headers=headers)

    def logout(
        self,
        *,
        session_id: Optional[str] = None,
        cookies: Optional[Mapping[str, str]] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Logout from the auth service."""

        payload = {"session_id": session_id} if session_id else None
        headers = self._build_cookie_header(cookies) if cookies else {}
        if extra_headers:
            headers.update(extra_headers)
        return self._request("POST", "/auth/logout", json_body=payload, headers=headers)

    def status(
        self,
        *,
        session_id: Optional[str] = None,
        cookies: Optional[Mapping[str, str]] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Get the status of the auth service."""

        headers = self._build_cookie_header(cookies) if cookies else {}
        if session_id:
            headers["X-Session-ID"] = session_id
        if extra_headers:
            headers.update(extra_headers)
        return self._request("GET", "/auth/status", headers=headers)

    def update_limits(
        self,
        *,
        per_user_limits: Mapping[str, Mapping[str, int]],
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Update the per-user limits of the auth service."""

        payload = {"per_user_limits": per_user_limits}
        headers: MutableMapping[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        return self._request("POST", "/auth/limits", json_body=payload, headers=headers)

    # --------------------- Internal helpers ---------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Make a request to the auth service."""

        url = f"{self._base_url}{path}"
        request_headers: MutableMapping[str, str] = dict(_JSON_HEADERS)
        request_headers.update(self._service_token_headers())
        if headers:
            request_headers.update(headers)

        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        req = Request(url, data=data, method=method.upper(), headers=request_headers)  # type: ignore[arg-type]
        try:
            with urlopen(req, timeout=self._timeout) as resp:  # type: ignore[call-arg]
                body = resp.read()
                status = resp.getcode()
                headers_map = {k: v for k, v in resp.headers.items()}
                cookies = self._extract_cookies(resp.headers)
                set_cookies = self._extract_set_cookie_headers(resp.headers)
                parsed = self._parse_json(body)
                return AuthServiceResponse(status_code=status, json=parsed, headers=headers_map, cookies=cookies, set_cookies=set_cookies, raw_body=body)
        except HTTPError as exc:  # type: ignore[arg-type]
            body = exc.read() if hasattr(exc, "read") else b""
            headers_map = {k: v for k, v in getattr(exc, "headers", {}).items()} if getattr(exc, "headers", None) else {}
            has_headers = getattr(exc, "headers", None)
            cookies = self._extract_cookies(exc.headers) if has_headers else {}
            set_cookies = self._extract_set_cookie_headers(exc.headers) if has_headers else ()
            parsed = self._parse_json(body)
            return AuthServiceResponse(status_code=getattr(exc, "code", 500), json=parsed, headers=headers_map, cookies=cookies, set_cookies=set_cookies, raw_body=body)
        except URLError as exc:  # type: ignore[arg-type]
            msg = getattr(exc, "reason", exc)
            raise ConnectionError(f"Auth service request failed: {msg}") from exc

    def _service_token_headers(self) -> Mapping[str, str]:
        """Build the service token headers."""

        headers: MutableMapping[str, str] = {}
        token: Optional[str] = None
        if self._cfg.token_secret:
            params = ServiceTokenParams(
                subject=self._cfg.subject,
                issuer=self._cfg.issuer,
                audience=self._cfg.audience,
                secret=self._cfg.token_secret,
                ttl_seconds=self._cfg.token_ttl_seconds,
                scope=self._cfg.token_scope,
            )
            token = sign_service_token(params)
            headers.update(build_auth_headers(token))
        elif self._cfg.static_token:
            token = self._cfg.static_token

        if token:
            headers.setdefault("X-Service-Token", token)
        return headers

    @staticmethod
    def _parse_json(body: bytes) -> Optional[Mapping[str, Any]]:
        """Parse the JSON body of the response."""

        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    @staticmethod
    def _extract_cookies(message: Any) -> Mapping[str, str]:
        """Extract the cookies from the response."""

        cookie_jar = SimpleCookie()
        if message is None:
            return {}
        values = []
        get_all = getattr(message, "get_all", None)
        if callable(get_all):
            raw = get_all("Set-Cookie")
            if raw:
                values.extend(raw)
        else:
            value = message.get("Set-Cookie") if hasattr(message, "get") else None
            if value:
                values.append(value)
        for value in values:
            try:
                cookie_jar.load(value)
            except Exception:
                continue
        return {k: morsel.value for k, morsel in cookie_jar.items()}

    @staticmethod
    def _extract_set_cookie_headers(message: Any) -> tuple[str, ...]:
        if message is None:
            return ()
        values: list[str] = []
        get_all = getattr(message, "get_all", None)
        if callable(get_all):
            raw = get_all("Set-Cookie")
            if raw:
                values.extend(raw)
        else:
            value = message.get("Set-Cookie") if hasattr(message, "get") else None
            if value:
                values.append(value)
        return tuple(values)

    @staticmethod
    def _build_cookie_header(cookies: Mapping[str, str]) -> MutableMapping[str, str]:
        """Build the cookie header."""
        
        header_value = "; ".join(f"{k}={v}" for k, v in cookies.items() if v is not None)
        return {"Cookie": header_value} if header_value else {}

