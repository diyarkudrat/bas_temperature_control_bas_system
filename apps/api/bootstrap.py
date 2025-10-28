"""API application bootstrap wiring.

Provides helpers to construct server_config, auth provider, metrics, Firestore
factory, and tenant middleware. Centralizes DI for the API app.
"""

from __future__ import annotations

from typing import Optional

from app_platform.config.config import get_server_config, ServerConfig
from adapters.db.firestore import build_service_factory_with_config, FirestoreServiceFactory
from adapters.providers import (
    MockAuth0Provider,
    DenyAllAuthProvider,
    build_auth0_provider,
)
from app_platform.observability.metrics import AuthMetrics
from apps.api.http.middleware import TenantMiddleware


def load_server_config() -> ServerConfig:
    return get_server_config()


def build_auth_runtime(cfg: ServerConfig):
    """Return (provider, metrics) based on server config."""
    provider_kind = (cfg.auth_provider or "mock").lower()
    try:
        if provider_kind == "auth0":
            domain = (cfg.auth0_domain or "").strip()
            audience = (cfg.auth0_audience or "").strip()
            if not domain or not audience:
                raise ValueError("AUTH0_DOMAIN and AUTH0_AUDIENCE are required for auth0 provider")
            issuer = f"https://{domain}/" if not domain.startswith("https://") else domain
            provider = build_auth0_provider({
                "issuer": issuer,
                "audience": audience,
            })
        elif provider_kind == "mock":
            if not cfg.use_emulators:
                provider = DenyAllAuthProvider()
            else:
                issuer = f"https://{cfg.auth0_domain}/" if cfg.auth0_domain else "https://mock.auth0/"
                provider = MockAuth0Provider(
                    audience=str(cfg.auth0_audience or "bas-api"),
                    issuer=issuer,
                )
        else:
            provider = DenyAllAuthProvider()
    except Exception:
        provider = DenyAllAuthProvider()
    metrics = AuthMetrics()
    return provider, metrics


def build_firestore_factory(cfg) -> Optional[FirestoreServiceFactory]:
    """Create Firestore factory if any Firestore feature is enabled."""
    try:
        if any([
            cfg.firestore.use_firestore_telemetry,
            cfg.firestore.use_firestore_auth,
            cfg.firestore.use_firestore_audit,
        ]):
            return build_service_factory_with_config(cfg)
    except Exception:
        pass
    return None


def build_tenant_middleware(auth_config, firestore_factory) -> Optional[TenantMiddleware]:
    if firestore_factory:
        return TenantMiddleware(auth_config, firestore_factory)
    return None


