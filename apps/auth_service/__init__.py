"""Auth service package bootstrap."""

from __future__ import annotations

from .main import bootstrap_runtime, create_app, register_healthcheck

__all__ = ["create_app", "bootstrap_runtime", "register_healthcheck"]

