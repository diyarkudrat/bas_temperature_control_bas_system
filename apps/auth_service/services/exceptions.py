"""Custom exceptions used across auth-service onboarding services."""

from __future__ import annotations


class ServiceConfigurationError(RuntimeError):
    """Raised when required configuration for a service is missing."""


class InviteRateLimitError(RuntimeError):
    """Raised when an invite request exceeds tenant-level quotas."""


class InviteConflictError(RuntimeError):
    """Raised when an invite already exists for the given tenant/email."""


class DuplicateEventError(RuntimeError):
    """Raised when a webhook event has already been processed."""


class UpstreamServiceError(RuntimeError):
    """Raised when a downstream dependency responds with an error."""


class UnauthorizedRequestError(RuntimeError):
    """Raised when an incoming request fails authentication or signature checks."""


