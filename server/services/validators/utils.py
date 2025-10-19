from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)


def load_json_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        if not os.path.exists(path):
            logger.info("File not found: %s", path)
            return None
        with open(path, "r") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to load JSON file %s: %s", path, exc)
        return None


def run_jsonschema_validation(config: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """
    Validate against JSON Schema if 'jsonschema' is available.
    Returns a list of error strings; empty list means no structural errors.
    """
    try:
        import jsonschema  # type: ignore
    except Exception:
        logger.info("jsonschema not installed; skipping structural validation")
        return []
    try:
        jsonschema.validate(instance=config, schema=schema)
        return []
    except Exception as exc:
        return [f"schema: {exc}"]


