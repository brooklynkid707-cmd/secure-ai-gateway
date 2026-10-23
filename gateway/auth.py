"""API-key identities, roles, token-bucket rate limiting and daily token budgets.

Identities live in ``config/identities.yaml``. Keys are never stored in clear:
the file holds ``sha256(key)`` and the gateway hashes the presented bearer
token before a constant-time comparison. The sample file ships with demo keys
whose plaintext is printed in the README purely so the selftest can run.

Rate limiting is a classic token bucket per identity (``requests_per_minute``
refill rate, ``burst`` capacity). Budgets are a daily counter of tokens
(upstream ``usage.total_tokens`` when present, otherwise an estimate). Both
are in-process; a multi-node deployment would back them with a shared store.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {name: i for i, name in enumerate(ROLES)}


def hash_key(key: str) -> str:
    """Return the hex SHA-256 digest used to store API keys at rest."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (about four characters per token) used when upstream reports no usage."""
    return max(1, len(text) // 4)


@dataclass
class Identity:
    """One API-key principal."""

    id: str
    role: str
    key_sha256: str
    requests_per_minute: int = 60
    burst: int = 20
    daily_token_budget: int = 200_000
    networks: list[str] = field(default_factory=list)
    disabled: bool = False
    description: str = ""

    def allows_network(self, client_ip: str) -> bool:
        """True when no identity-level network restriction exists or ``client_ip`` matches one."""
        if not self.networks:
            return True
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        for net in self.networks:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False


class TokenBucket:
    """Thread-safe token bucket."""

    def __init__(self, rate_per_minute: int, capacity: int) -> None:
        self.rate = max(rate_per_minute, 1) / 60.0
        self.capacity = max(capacity, 1)
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def try_consume(self, amount: float = 1.0, now: float | None = None) -> bool:
        """Consume ``amount`` tokens if available; refill based on elapsed time first."""
        with self._lock:
            now = time.monotonic() if now is None else now
            elapsed = max(0.0, now - self.updated)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


@dataclass
class BudgetState:
    """Tokens spent today for one identity."""

    day: str
    spent: int = 0


class AuthError(Exception):
    """Authentication or quota failure; ``status`` is the HTTP status to return."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class Authenticator:
    """Loads identities and enforces key validity, rate limits and budgets."""

    def __init__(self, identities: list[Identity]) -> None:
        self._by_hash: dict[str, Identity] = {i.key_sha256: i for i in identities}
        self._by_id: dict[str, Identity] = {i.id: i for i in identities}
        self._buckets: dict[str, TokenBucket] = {}
        self._budgets: dict[str, BudgetState] = {}
        self._lock = threading.Lock()

    # ----------------------------------------------------------- loading
    @classmethod
    def from_yaml(cls, path: str | Path) -> "Authenticator":
        """Parse ``identities.yaml``."""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls([cls._parse(item) for item in data.get("identities", [])])

    @staticmethod
    def _parse(item: dict[str, Any]) -> Identity:
        role = str(item.get("role", "viewer"))
        if role not in ROLES:
            raise ValueError(f"identity {item.get('id')!r}: unknown role {role!r}")
        return Identity(
            id=str(item["id"]),
            role=role,
            key_sha256=str(item["key_sha256"]).lower(),
            requests_per_minute=int(item.get("requests_per_minute", 60)),
            burst=int(item.get("burst", 20)),
            daily_token_budget=int(item.get("daily_token_budget", 200_000)),
            networks=[str(n) for n in item.get("networks", []) or []],
            disabled=bool(item.get("disabled", False)),
            description=str(item.get("description", "")),
        )

    def identities(self) -> list[Identity]:
        """All loaded identities (for the admin endpoint; hashes are not exposed there)."""
        return list(self._by_id.values())

    def get(self, identity_id: str) -> Identity | None:
        """Look an identity up by id."""
        return self._by_id.get(identity_id)

    # ------------------------------------------------------- authenticate
    def authenticate(self, authorization_header: str | None) -> Identity:
        """Resolve a ``Bearer <key>`` header to an enabled identity or raise 401."""
        if not authorization_header or not authorization_header.lower().startswith("bearer "):
            raise AuthError(401, "missing_api_key", "Authorization: Bearer <api-key> header required")
        key = authorization_header[7:].strip()
        if not key:
            raise AuthError(401, "missing_api_key", "empty bearer token")
        digest = hash_key(key)
        for stored, identity in self._by_hash.items():
            if hmac.compare_digest(stored, digest):
                if identity.disabled:
                    raise AuthError(401, "key_disabled", "this API key has been revoked")
                return identity
        raise AuthError(401, "invalid_api_key", "unknown API key")

    # ----------------------------------------------------------- limits
    def check_rate_limit(self, identity: Identity) -> None:
        """Consume one request token or raise 429."""
        with self._lock:
            bucket = self._buckets.get(identity.id)
            if bucket is None:
                bucket = TokenBucket(identity.requests_per_minute, identity.burst)
                self._buckets[identity.id] = bucket
        if not bucket.try_consume():
            raise AuthError(
                429,
                "rate_limited",
                f"rate limit exceeded ({identity.requests_per_minute}/min, burst {identity.burst})",
            )

    def _budget(self, identity: Identity, today: str) -> BudgetState:
        state = self._budgets.get(identity.id)
        if state is None or state.day != today:
            state = BudgetState(day=today)
            self._budgets[identity.id] = state
        return state

    def check_budget(self, identity: Identity, estimated_tokens: int, today: str | None = None) -> None:
        """Raise 429 when today's spend plus this request's estimate exceeds the daily budget."""
        today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            state = self._budget(identity, today)
            if state.spent + estimated_tokens > identity.daily_token_budget:
                raise AuthError(
                    429,
                    "budget_exceeded",
                    f"daily token budget exhausted ({state.spent}/{identity.daily_token_budget} used)",
                )

    def record_usage(self, identity: Identity, tokens: int, today: str | None = None) -> int:
        """Add ``tokens`` to today's spend and return the running total."""
        today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            state = self._budget(identity, today)
            state.spent += max(0, tokens)
            return state.spent

    def usage_today(self, identity: Identity, today: str | None = None) -> int:
        """Tokens spent today by ``identity``."""
        today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            return self._budget(identity, today).spent

    def reset(self) -> None:
        """Forget all rate-limit and budget state (tests)."""
        with self._lock:
            self._buckets.clear()
            self._budgets.clear()
