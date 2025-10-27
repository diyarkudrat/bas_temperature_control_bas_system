import pytest

from auth.managers import UserAuthManager, RateLimitedError, TokenVerificationError, RevokedTokenError


class FakeProvider:
    def __init__(self, claims=None, err=None):
        self.claims = claims or {"sub": "u1", "jti": "tid-1"}
        self.err = err
    def verify_token(self, token: str):
        if self.err:
            raise self.err
        return dict(self.claims)
    def get_user_roles(self, uid: str):
        return ["operator"]


class FakeLimiter:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []
    def is_allowed(self, ip, username=None):
        return self.allowed, "Allowed" if self.allowed else "Denied"
    def record_attempt(self, ip, username=None):
        self.calls.append((ip, username))


class FakeRevocations:
    def __init__(self, revoked=False):
        self.revoked = revoked
    def is_revoked(self, token_id: str) -> bool:
        return self.revoked


def test_successful_verification_path():
    mgr = UserAuthManager(
        provider=FakeProvider(claims={"sub": "u1", "jti": "tid-ok"}),
        revocations=FakeRevocations(revoked=False),
        limiter=FakeLimiter(allowed=True),
    )
    claims = mgr.verify_request_token("tok", ip="1.2.3.4", username_hint="alice")
    assert claims["sub"] == "u1"


def test_rate_limited_raises_and_records_attempt():
    limiter = FakeLimiter(allowed=False)
    mgr = UserAuthManager(
        provider=FakeProvider(),
        revocations=FakeRevocations(revoked=False),
        limiter=limiter,
    )
    with pytest.raises(RateLimitedError):
        mgr.verify_request_token("tok", ip="1.2.3.4", username_hint="alice")
    # attempt should be recorded even when denied
    assert limiter.calls, "expected record_attempt to be called"


def test_token_verification_error_wrapped():
    mgr = UserAuthManager(
        provider=FakeProvider(err=ValueError("bad token")),
        revocations=FakeRevocations(revoked=False),
        limiter=FakeLimiter(allowed=True),
    )
    with pytest.raises(TokenVerificationError):
        mgr.verify_request_token("tok", ip="1.2.3.4")


def test_revoked_token_raises():
    mgr = UserAuthManager(
        provider=FakeProvider(claims={"sub": "u1", "jti": "tid-rev"}),
        revocations=FakeRevocations(revoked=True),
        limiter=FakeLimiter(allowed=True),
    )
    with pytest.raises(RevokedTokenError):
        mgr.verify_request_token("tok", ip="1.2.3.4")


