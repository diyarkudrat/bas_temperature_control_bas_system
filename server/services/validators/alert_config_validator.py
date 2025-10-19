from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import ValidationResult, Validator
from .utils import load_json_file, run_jsonschema_validation

logger = logging.getLogger(__name__)

SEVERITIES: Set[str] = {"info", "warning", "error", "critical"}
CHANNELS: Set[str] = {"sms", "email"}
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
EMAIL_RE = re.compile(r".+@.+")


def _load_schema() -> Optional[Dict[str, Any]]:
    return load_json_file("server/config/alert_config.json")


def _normalize_defaults(cfg: Dict[str, Any]) -> None:
    providers = cfg.get("providers", {}) or {}
    email = providers.get("email")
    if isinstance(email, dict) and "use_tls" not in email:
        email["use_tls"] = True
    routing = cfg.get("routing", {}) or {}
    if "default_channels" in routing:
        seen = set()
        uniq = []
        for ch in routing["default_channels"]:
            if ch not in seen:
                uniq.append(ch)
                seen.add(ch)
        routing["default_channels"] = uniq


def _collect_channels_in_use(cfg: Dict[str, Any]) -> Set[str]:
    in_use: Set[str] = set()
    routing = cfg.get("routing", {}) or {}
    default_channels = routing.get("default_channels", []) or []
    in_use.update(default_channels)
    severity_routes = routing.get("severity_routes", {}) or {}
    for _, channels in severity_routes.items():
        in_use.update(channels or [])
    tenants = routing.get("tenants", {}) or {}
    for _, tenant_cfg in tenants.items():
        if isinstance(tenant_cfg, dict):
            in_use.update(tenant_cfg.get("channels", []) or [])
    return in_use & CHANNELS


def _semantic_checks(cfg: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    version = cfg.get("version")
    if not isinstance(version, str) or not SEMVER_RE.match(version):
        errors.append("version: must be a semantic version string like '1.0.0'")

    providers = cfg.get("providers", {}) or {}
    routing = cfg.get("routing", {}) or {}

    default_channels = routing.get("default_channels")
    if not isinstance(default_channels, list) or not default_channels:
        errors.append("routing.default_channels: must be a non-empty array")
    else:
        invalid = [c for c in default_channels if c not in CHANNELS]
        if invalid:
            errors.append(f"routing.default_channels: invalid channels {invalid}")

    severity_routes = routing.get("severity_routes", {}) or {}
    for sev, channels in severity_routes.items():
        if sev not in SEVERITIES:
            errors.append(f"routing.severity_routes: invalid severity '{sev}'")
            continue
        if not isinstance(channels, list):
            errors.append(f"routing.severity_routes.{sev}: must be an array")
            continue
        invalid = [c for c in channels if c not in CHANNELS]
        if invalid:
            errors.append(f"routing.severity_routes.{sev}: invalid channels {invalid}")

    tenants = routing.get("tenants", {}) or {}
    if not isinstance(tenants, dict):
        errors.append("routing.tenants: must be an object")
    else:
        for tenant_id, tcfg in tenants.items():
            if not isinstance(tcfg, dict):
                errors.append(f"routing.tenants.{tenant_id}: must be an object")
                continue
            channels = tcfg.get("channels", [])
            if channels:
                invalid = [c for c in channels if c not in CHANNELS]
                if invalid:
                    errors.append(f"routing.tenants.{tenant_id}.channels: invalid channels {invalid}")
            email_to = tcfg.get("email_to", [])
            if email_to:
                if not isinstance(email_to, list) or any(not isinstance(x, str) for x in email_to):
                    errors.append(f"routing.tenants.{tenant_id}.email_to: must be an array of strings")
                else:
                    bad = [x for x in email_to if not EMAIL_RE.match(x)]
                    if bad:
                        errors.append(f"routing.tenants.{tenant_id}.email_to: invalid emails {bad}")

    channels_in_use = _collect_channels_in_use(cfg)
    if "sms" in channels_in_use:
        tw = providers.get("twilio")
        if not isinstance(tw, dict):
            errors.append("providers.twilio: required because 'sms' is referenced in routing")
        else:
            sid = tw.get("account_sid")
            tok = tw.get("auth_token")
            frm = tw.get("from_number")
            mss = tw.get("messaging_service_sid")
            if not sid or not tok:
                errors.append("providers.twilio: account_sid and auth_token are required")
            if not frm and not mss:
                errors.append("providers.twilio: require either from_number or messaging_service_sid")
    if "email" in channels_in_use:
        em = providers.get("email")
        if not isinstance(em, dict):
            errors.append("providers.email: required because 'email' is referenced in routing")
        else:
            if not em.get("smtp_host"):
                errors.append("providers.email.smtp_host: required")
            port = em.get("smtp_port")
            if not isinstance(port, int) or port <= 0 or port > 65535:
                errors.append("providers.email.smtp_port: must be an integer between 1 and 65535")

    limits = cfg.get("limits", {}) or {}
    if limits:
        for key in ("max_sms_per_minute", "max_email_per_minute", "burst"):
            if key in limits and (not isinstance(limits[key], int) or limits[key] <= 0):
                errors.append(f"limits.{key}: must be a positive integer")

    return errors, warnings


class AlertConfigValidator(Validator):
    def __init__(self, schema: Optional[Dict[str, Any]] = None) -> None:
        self._schema = schema

    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        if not isinstance(config, dict):
            return ValidationResult(False, ["config: must be a JSON object"], [])

        cfg = json.loads(json.dumps(config))  # deep copy

        schema_to_use = self._schema or _load_schema()
        schema_errors: List[str] = []
        if schema_to_use:
            schema_errors = run_jsonschema_validation(cfg, schema_to_use)

        _normalize_defaults(cfg)

        semantic_errors, warnings = _semantic_checks(cfg)
        all_errors = schema_errors + semantic_errors
        if all_errors:
            return ValidationResult(False, all_errors, warnings, None)
        return ValidationResult(True, [], warnings, cfg)


def validate_alert_config(config: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> ValidationResult:
    return AlertConfigValidator(schema).validate(config)


