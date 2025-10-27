import json
from unittest.mock import patch

from server.config.config import ServerConfig


def test_path_rules_env_parsing_valid_regex():
    rules = json.dumps([
        {"pattern": "/api/secure/.*", "level": "CRITICAL"},
        ["^/api/public$", "standard"],
    ])
    with patch.dict('os.environ', {"BAS_PATH_SENS_RULES": rules}):
        cfg = ServerConfig.from_env()
        assert isinstance(cfg.PATH_SENSITIVITY_RULES, list)
        assert cfg.PATH_SENSITIVITY_RULES[0][1] == "critical"


def test_path_rules_env_parsing_invalid_regex_graceful():
    rules = json.dumps([
        {"pattern": "[unclosed", "level": "critical"},
    ])
    with patch.dict('os.environ', {"BAS_PATH_SENS_RULES": rules}):
        cfg = ServerConfig.from_env()
        # invalid rule should be dropped
        assert cfg.PATH_SENSITIVITY_RULES == []


def test_breaker_thresholds_override_valid():
    overrides = json.dumps({"failure_threshold": 10, "window_seconds": 60, "half_open_after_seconds": 5})
    with patch.dict('os.environ', {"BREAKER_THRESHOLDS": overrides}):
        cfg = ServerConfig.from_env()
        assert cfg.breaker.failure_threshold == 10
        assert cfg.breaker.window_seconds == 60
        assert cfg.breaker.half_open_after_seconds == 5


def test_breaker_thresholds_override_invalid_ignored():
    overrides = json.dumps({"failure_threshold": -1, "window_seconds": "bad"})
    with patch.dict('os.environ', {"BREAKER_THRESHOLDS": overrides}):
        cfg = ServerConfig.from_env()
        # Invalid overrides should not crash and keep defaults/clamped values
        assert cfg.breaker.failure_threshold > 0
        assert cfg.breaker.window_seconds > 0


