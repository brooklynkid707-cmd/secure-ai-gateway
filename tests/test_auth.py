"""Identity loading, key hashing, rate limiting and budgets."""

from __future__ import annotations

import pytest

from gateway.auth import AuthError, Authenticator, Identity, TokenBucket, hash_key
from tests.conftest import CONFIG

VIEWER_KEY = "sag-viewer-demo-key-0001"


def test_keys_are_stored_hashed() -> None:
    text = (CONFIG / "identities.yaml").read_text()
    assert VIEWER_KEY not in text.replace("# " + VIEWER_KEY, "")  # only the comment mentions it
    assert hash_key(VIEWER_KEY) in text


def test_authenticate_roles() -> None:
    auth = Authenticator.from_yaml(CONFIG / "identities.yaml")
    assert auth.authenticate(f"Bearer {VIEWER_KEY}").role == "viewer"
    assert auth.authenticate("Bearer sag-analyst-demo-key-0002").role == "analyst"
    assert auth.authenticate("Bearer sag-admin-demo-key-0003").role == "admin"


@pytest.mark.parametrize(
    "header, code",
    [(None, "missing_api_key"), ("Basic abc", "missing_api_key"), ("Bearer ", "missing_api_key"),
     ("Bearer nope", "invalid_api_key"), ("Bearer sag-revoked-demo-key-0007", "key_disabled")],
)
def test_authenticate_failures(header, code) -> None:
    auth = Authenticator.from_yaml(CONFIG / "identities.yaml")
    with pytest.raises(AuthError) as exc:
        auth.authenticate(header)
    assert exc.value.code == code
    assert exc.value.status == 401


def test_unknown_role_rejected(tmp_path) -> None:
    p = tmp_path / "ids.yaml"
    p.write_text("identities:\n  - id: x\n    role: superuser\n    key_sha256: 'ab'\n")
    with pytest.raises(ValueError):
        Authenticator.from_yaml(p)


def test_token_bucket_refills() -> None:
    bucket = TokenBucket(rate_per_minute=60, capacity=2)  # 1 token/sec
    assert bucket.try_consume(now=0.0)
    assert bucket.try_consume(now=0.0)
    assert not bucket.try_consume(now=0.0)
    assert not bucket.try_consume(now=0.5)
    assert bucket.try_consume(now=1.01)


def test_rate_limit_via_authenticator() -> None:
    ident = Identity("svc", "analyst", "x", requests_per_minute=60, burst=3)
    auth = Authenticator([ident])
    for _ in range(3):
        auth.check_rate_limit(ident)
    with pytest.raises(AuthError) as exc:
        auth.check_rate_limit(ident)
    assert exc.value.status == 429 and exc.value.code == "rate_limited"


def test_daily_budget_and_reset() -> None:
    ident = Identity("svc", "analyst", "x", daily_token_budget=100)
    auth = Authenticator([ident])
    auth.check_budget(ident, 40, today="2026-10-23")
    assert auth.record_usage(ident, 70, today="2026-10-23") == 70
    with pytest.raises(AuthError) as exc:
        auth.check_budget(ident, 40, today="2026-10-23")
    assert exc.value.code == "budget_exceeded"
    auth.check_budget(ident, 40, today="2026-10-24")  # new day, new budget
    assert auth.usage_today(ident, today="2026-10-24") == 0


def test_identity_network_pinning() -> None:
    ident = Identity("p", "analyst", "x", networks=["203.0.113.0/24"])
    assert ident.allows_network("203.0.113.9")
    assert not ident.allows_network("198.51.100.9")
    assert not ident.allows_network("not-an-ip")
    assert Identity("q", "analyst", "x").allows_network("198.51.100.9")
