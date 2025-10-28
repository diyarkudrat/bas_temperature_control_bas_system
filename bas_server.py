"""Shim for legacy imports during migration.

This module re-exports the Flask app and symbols from apps.api.main to avoid
breaking existing imports and tests while migrating file structure.
"""

from apps.api.main import *  # noqa


