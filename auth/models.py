"""Compatibility layer re-exporting domain authentication models."""

from domains.auth.models import Session, User

__all__ = ["User", "Session"]


