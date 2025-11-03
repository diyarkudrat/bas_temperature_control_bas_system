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
from typing import Any, Mapping, MutableMapping, Optional, Sequence

try:  # pragma: no cover - stdlib availability validated at runtime
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:  # pragma: no cover
    Request = None  # type: ignore
    urlopen = None  # type: ignore
    HTTPError = Exception  # type: ignore
    URLError = Exception  # type: ignore

from app_platform.security import (
    IssuedServiceToken,
    ServiceKeySet,
    ServiceTokenError,
    build_auth_headers,
    issue_service_jwt,
    load_service_keyset_from_env,
)


logger = logging.getLogger(__name__)


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
    token_scope: Optional[str] = None
    token_ttl_seconds: int = 30
    forward_remote_addr_header: Optional[str] = "X-Forwarded-For"
    keyset: Optional[ServiceKeySet] = None
    keyset_env_prefix: str = "AUTH_SERVICE_TOKEN"
    allowed_algorithms: Optional[Sequence[str]] = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AuthServiceClientConfig":
        """Load configuration from environment variables."""

        env = env or os.environ
        base_url = env.get("AUTH_SERVICE_URL", "http://localhost:9090").strip()
        timeout = float(env.get("AUTH_SERVICE_TIMEOUT_S", "5.0"))
        auth0_domain = env.get("AUTH0_DOMAIN")
        auth0_audience = env.get("AUTH0_API_AUDIENCE")
        audience = env.get("AUTH_SERVICE_TOKEN_AUDIENCE") or auth0_audience or "bas-auth"
        issuer_env = env.get("AUTH_SERVICE_TOKEN_ISSUER")
        if issuer_env:
            issuer = issuer_env
        elif auth0_domain:
            issuer = f"https://{auth0_domain.strip().rstrip('/')}/"
        else:
            issuer = "bas-api"
        subject = env.get("AUTH_SERVICE_TOKEN_SUBJECT", "api-backend")
        scope = env.get("AUTH_SERVICE_TOKEN_SCOPE") or None
        ttl = int(env.get("AUTH_SERVICE_TOKEN_TTL_S", "30"))
        header_name = env.get("AUTH_SERVICE_REMOTE_ADDR_HEADER", "X-Forwarded-For") or None
        keyset_prefix = env.get("AUTH_SERVICE_TOKEN_PREFIX", "AUTH_SERVICE_TOKEN") or "AUTH_SERVICE_TOKEN"
        alg_env = env.get("AUTH_SERVICE_TOKEN_ALGORITHMS")
        allowed_algorithms = (
            tuple(alg.strip() for alg in alg_env.split(",") if alg.strip())
            if alg_env
            else None
        )

        return cls(
            base_url=base_url,
            timeout_seconds=timeout,
            audience=audience,
            issuer=issuer,
            subject=subject,
            token_scope=scope,
            token_ttl_seconds=ttl,
            forward_remote_addr_header=header_name,
            keyset_env_prefix=keyset_prefix,
            allowed_algorithms=allowed_algorithms,
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

        self._tenant_header = "X-BAS-Tenant"
        self._allowed_algorithms = (
            tuple(alg.upper() for alg in config.allowed_algorithms)
            if config.allowed_algorithms
            else None
        )
        self._forward_remote_header = config.forward_remote_addr_header

        self._token_ttl_seconds = max(1, min(int(config.token_ttl_seconds), 60))
        if config.token_ttl_seconds > 60:
            self._logger.warning(
                "Auth service token TTL capped at 60 seconds",
                extra={"configured": config.token_ttl_seconds},
            )

        try:
            resolved_keyset = config.keyset or self._load_service_keyset(config.keyset_env_prefix)
        except ServiceTokenError as exc:
            self._logger.error(
                "Unable to load auth service keyset",
                extra={"prefix": config.keyset_env_prefix},
                exc_info=True,
            )
            raise RuntimeError("Auth service keyset configuration invalid") from exc
        self._keyset: ServiceKeySet = resolved_keyset

        reserved = {
            "authorization",
            "x-service-token",
            "x-service-token-kid",
            "x-service-token-exp",
            "x-service-token-nonce",
            self._tenant_header.lower(),
        }
        if self._forward_remote_header:
            reserved.add(self._forward_remote_header.lower())
        self._reserved_headers = reserved
        self._reserved_passthrough = {
            name.lower()
            for name in (self._tenant_header, self._forward_remote_header)
            if name
        }

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
        if extra_headers:
            headers.update(self._sanitize_outbound_headers(extra_headers))
        if tenant_id:
            headers[self._tenant_header] = tenant_id
        if remote_addr and self._forward_remote_header:
            headers[self._forward_remote_header] = remote_addr
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
            headers.update(self._sanitize_outbound_headers(extra_headers))
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
            headers.update(self._sanitize_outbound_headers(extra_headers))
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
            headers.update(self._sanitize_outbound_headers(extra_headers))
        return self._request("POST", "/auth/limits", json_body=payload, headers=headers)

    def create_invite(
        self,
        *,
        tenant_id: str,
        payload: Mapping[str, Any],
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> AuthServiceResponse:
        """Create an invite via the auth service."""

        body = dict(payload)
        body.setdefault("tenantId", tenant_id)
        headers: MutableMapping[str, str] = {}
        if extra_headers:
            headers.update(self._sanitize_outbound_headers(extra_headers))
        return self._request("POST", "/auth/invite", json_body=body, headers=headers)

    # --------------------- Internal helpers ---------------------
    def _load_service_keyset(self, prefix: str) -> ServiceKeySet:
        keyset = load_service_keyset_from_env(prefix=prefix)
        if self._allowed_algorithms:
            allowed = {alg.upper() for alg in self._allowed_algorithms}
            invalid = [key.kid for key in keyset.keys() if key.alg.upper() not in allowed]
            if invalid:
                raise ServiceTokenError(
                    f"Unsupported algorithm(s) for key(s): {', '.join(invalid)}"
                )
        return keyset

    def _sanitize_outbound_headers(
        self,
        headers: Optional[Mapping[str, str]],
        *,
        allow: Optional[Sequence[str]] = None,
    ) -> MutableMapping[str, str]:
        if not headers:
            return {}
        allowed = {name.lower() for name in allow or ()}
        sanitized: MutableMapping[str, str] = {}
        for key, value in headers.items():
            if value is None:
                continue
            lower = key.lower()
            if lower in self._reserved_headers and lower not in allowed:
                continue
            sanitized[key] = value
        return sanitized

    def _issue_service_token(self) -> IssuedServiceToken:
        try:
            return issue_service_jwt(
                self._keyset,
                subject=self._cfg.subject,
                audience=self._cfg.audience,
                issuer=self._cfg.issuer,
                ttl_seconds=self._token_ttl_seconds,
                scope=self._cfg.token_scope,
            )
        except ServiceTokenError as exc:
            self._logger.error(
                "Failed to issue auth service JWT",
                extra={
                    "subject": self._cfg.subject,
                    "audience": self._cfg.audience,
                    "issuer": self._cfg.issuer,
                },
                exc_info=True,
            )
            raise

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
            sanitized = self._sanitize_outbound_headers(headers, allow=self._reserved_passthrough)
            request_headers.update(sanitized)

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

        issued = self._issue_service_token()
        headers: MutableMapping[str, str] = dict(build_auth_headers(issued))
        headers["X-Service-Token-Kid"] = issued.kid
        headers["X-Service-Token-Exp"] = str(issued.expires_at)
        nonce = issued.claims.get("nonce")
        if nonce:
            headers["X-Service-Token-Nonce"] = str(nonce)
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

