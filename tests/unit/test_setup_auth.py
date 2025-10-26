from __future__ import annotations

from typing import Any, Dict, Optional

from scripts.setup_auth import ensure_auth0_roles_action, _compute_checksum, _action_code_default


class _FakeMgmt:
    def __init__(self, present: bool = False, code: Optional[str] = None) -> None:
        self._action: Optional[Dict[str, Any]] = None
        if present:
            self._action = {"id": "act_1", "name": "BAS_RolesToClaims", "code": code or _action_code_default(), "supported_triggers": [{"id": "post-login"}]}
        self.deploy_calls = 0
        self.update_calls = 0
        self.create_calls = 0

    def get_action_by_name(self, name: str) -> Optional[Dict[str, Any]]:  # noqa: ARG002
        return self._action

    def create_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.create_calls += 1
        self._action = {"id": "act_new", **payload}
        return self._action

    def update_action(self, action_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG002
        self.update_calls += 1
        if self._action is None:
            self._action = {"id": action_id}
        self._action["code"] = payload.get("code", self._action.get("code"))
        return self._action

    def deploy_action(self, action_id: str) -> Dict[str, Any]:  # noqa: ARG002
        self.deploy_calls += 1
        return {"status": "deployed", "id": action_id}


def test_idempotent_deploy_create_then_unchanged():
    mgmt = _FakeMgmt(present=False)
    first = ensure_auth0_roles_action(mgmt)
    assert first["status"] == "created"
    assert mgmt.create_calls == 1
    second = ensure_auth0_roles_action(mgmt)
    assert second["status"] == "unchanged"
    assert mgmt.update_calls == 0


def test_update_when_code_changes():
    original = _action_code_default()
    modified = original + "\n// change\n"
    mgmt = _FakeMgmt(present=True, code=original)
    out = ensure_auth0_roles_action(mgmt, code_override=modified)
    assert out["status"] == "updated"
    assert mgmt.update_calls == 1
    # checksum should reflect modified code
    assert out["checksum"] == _compute_checksum(modified)


