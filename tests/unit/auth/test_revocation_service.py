import time

from adapters.cache.redis.revocation_service import RevocationService


class FakeRedis:
    """Minimal in-memory Redis subset for RevocationService tests."""

    def __init__(self):
        self._zsets = {}
        self._hashes = {}

    # ZSET ops
    def zadd(self, key, mapping, nx=False):
        z = self._zsets.setdefault(key, {})
        for member, score in mapping.items():
            if nx and member in z:
                continue
            z[member] = float(score)

    def zscore(self, key, member):
        z = self._zsets.get(key, {})
        return z.get(member, None)

    def zrangebyscore(self, key, min="-inf", max="+inf"):
        z = self._zsets.get(key, {})
        lo = float("-inf") if min in ("-inf", None) else float(min)
        hi = float("inf") if max in ("+inf", None) else float(max)
        return [m for m, s in sorted(z.items(), key=lambda kv: kv[1]) if lo <= s <= hi]

    def zremrangebyscore(self, key, min, max):
        z = self._zsets.get(key, {})
        lo = float("-inf") if min in ("-inf", None) else float(min)
        hi = float("inf") if max in ("+inf", None) else float(max)
        to_del = [m for m, s in z.items() if lo <= s <= hi]
        for m in to_del:
            del z[m]
        return len(to_del)

    # HASH ops
    def hset(self, key, field, value):
        h = self._hashes.setdefault(key, {})
        h[field] = value

    def hget(self, key, field):
        h = self._hashes.get(key, {})
        return h.get(field, None)

    def hdel(self, key, *fields):
        h = self._hashes.get(key, {})
        count = 0
        for f in fields:
            if f in h:
                del h[f]
                count += 1
        return count


def test_add_revocation():
    fake = FakeRedis()
    svc = RevocationService(fake, ttl_s=60)
    svc.add_revocation("tok123", reason="compromised")

    # Present in set
    assert fake.zscore("auth:revocations", "tok123") is not None
    # Reason stored
    assert svc.get_revocation_reason("tok123") == "compromised"


def test_is_revoked_positive():
    fake = FakeRedis()
    now = 1000.0

    def now_func():
        return now

    svc = RevocationService(fake, ttl_s=60, time_func=now_func)
    svc.add_revocation("tokA", reason="user_request")

    assert svc.is_revoked("tokA") is True


def test_is_revoked_negative_after_ttl():
    fake = FakeRedis()
    base = 1000.0
    current = [base]

    def now_func():
        return current[0]

    svc = RevocationService(fake, ttl_s=10, time_func=now_func)
    svc.add_revocation("tokB", reason="expired")

    # Advance beyond TTL
    current[0] = base + 11
    assert svc.is_revoked("tokB") is False


def test_write_rate_monitoring_window():
    fake = FakeRedis()
    base = 1000.0
    current = [base]

    def now_func():
        return current[0]

    svc = RevocationService(fake, ttl_s=None, time_func=now_func)
    # Burst 3 writes within 1s
    svc.add_revocation("t1")
    svc.add_revocation("t2")
    svc.add_revocation("t3")
    assert svc.write_rate_last_sec() == 3

    # Move past window
    current[0] = base + 2.0
    assert svc.write_rate_last_sec() == 0


