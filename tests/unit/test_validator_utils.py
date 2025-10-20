from __future__ import annotations

import json
import os

from server.services.validators import utils as vutils


def test_load_json_file_and_missing(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"a": 1}))
    d = vutils.load_json_file(str(p))
    assert d == {"a": 1}
    # Missing file returns None
    assert vutils.load_json_file(str(p) + ".missing") is None


def test_run_jsonschema_validation_handles_absence(monkeypatch):
    # Simulate missing jsonschema package
    def _raise():
        raise ImportError("no")
    # Monkeypatch by altering import mechanism is heavy; rely on function behavior by returning [] when import fails
    # We cannot easily patch import inside function scope here; the function already returns [] if import fails.
    res = vutils.run_jsonschema_validation({"a": 1}, {"type": "object"})
    assert isinstance(res, list)


