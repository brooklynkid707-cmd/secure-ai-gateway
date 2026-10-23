"""Policy model and decision logic.

A policy file (see ``config/balanced.yaml``) has these top-level sections:

``roles``      per-role rules: allowed models, max tokens, tools, denied topics,
               hours/days, networks, whether client system prompts are honoured
``topics``     named regex sets describing *organisational* data classes
               (source code, customer records, ...) that some roles may not send
``dlp``        detector actions (redact/block/warn/ignore) and defaults
``injection``  warn/block thresholds and the optional LLM classifier switch
``output``     leak, secret and sanitisation behaviour on the response path
``system_prompt`` the text the gateway prepends (canary is appended at runtime)
``audit``      log path

Evaluation order in ``PolicyEngine.evaluate`` is fixed and documented in
``docs/policy-reference.md``; the first failing check wins.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


@dataclass
class Topic:
    """A named class of organisational data recognised by regex patterns."""

    name: str
    description: str
    patterns: list[re.Pattern[str]]
    min_matches: int = 1

    def matches(self, text: str) -> int:
        """Count how many distinct patterns hit."""
        return sum(1 for p in self.patterns if p.search(text))


@dataclass
class RolePolicy:
    """Rules for one role."""

    name: str
    allow: bool = True
    models: list[str] = field(default_factory=list)
    max_tokens: int = 1024
    tools: list[str] = field(default_factory=list)
    deny_topics: list[str] = field(default_factory=list)
    hours: tuple[int, int] | None = None  # minutes since midnight UTC, inclusive start / exclusive end
    days: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    allow_client_system_prompt: bool = False
    max_messages: int = 50
    max_input_chars: int = 20_000


@dataclass
class Policy:
    """Fully parsed policy."""

    name: str
    description: str
    roles: dict[str, RolePolicy]
    topics: dict[str, Topic]
    dlp_actions: dict[str, str]
    dlp_default_action: str
    dlp_enabled: list[str] | None
    injection_warn: float
    injection_block: float
    injection_use_classifier: bool
    injection_classifier_weight: float
    output_leak_block: bool
    output_overlap_threshold: float
    output_secret_action: str
    output_pii_action: str
    output_sanitize_html: bool
    output_allowed_image_hosts: list[str]
    system_prompt: str
    audit_path: str
    raw: dict[str, Any]


@dataclass
class Decision:
    """Result of evaluating a request against the policy."""

    allowed: bool
    code: str = "ok"
    message: str = ""
    status: int = 200
    warnings: list[str] = field(default_factory=list)
    max_tokens: int | None = None
    allowed_tools: list[str] = field(default_factory=list)
    topics_hit: list[str] = field(default_factory=list)
    client_system_prompt_allowed: bool = False


def _parse_hours(value: Any) -> tuple[int, int] | None:
    if not value:
        return None
    if isinstance(value, dict):
        start, end = str(value.get("start", "00:00")), str(value.get("end", "24:00"))
    else:
        start, end = [s.strip() for s in str(value).split("-", 1)]

    def _mins(s: str) -> int:
        h, m = s.split(":")
        return int(h) * 60 + int(m)

    return _mins(start), _mins(end)


def load_policy(path: str | Path) -> Policy:
    """Parse and validate a policy YAML file."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    topics: dict[str, Topic] = {}
    for name, spec in (raw.get("topics") or {}).items():
        topics[name] = Topic(
            name=name,
            description=str(spec.get("description", "")),
            patterns=[re.compile(p, re.MULTILINE) for p in spec.get("patterns", [])],
            min_matches=int(spec.get("min_matches", 1)),
        )
    roles: dict[str, RolePolicy] = {}
    for name, spec in (raw.get("roles") or {}).items():
        spec = spec or {}
        for t in spec.get("deny_topics", []) or []:
            if t not in topics:
                raise ValueError(f"role {name!r} denies unknown topic {t!r}")
        days = [str(d).lower()[:3] for d in spec.get("days", []) or []]
        for d in days:
            if d not in DAY_NAMES:
                raise ValueError(f"role {name!r}: unknown day {d!r}")
        roles[name] = RolePolicy(
            name=name,
            allow=bool(spec.get("allow", True)),
            models=[str(m) for m in spec.get("models", []) or []],
            max_tokens=int(spec.get("max_tokens", 1024)),
            tools=[str(t) for t in spec.get("tools", []) or []],
            deny_topics=[str(t) for t in spec.get("deny_topics", []) or []],
            hours=_parse_hours(spec.get("hours")),
            days=days,
            networks=[str(n) for n in spec.get("networks", []) or []],
            allow_client_system_prompt=bool(spec.get("allow_client_system_prompt", False)),
            max_messages=int(spec.get("max_messages", 50)),
            max_input_chars=int(spec.get("max_input_chars", 20_000)),
        )
    dlp = raw.get("dlp") or {}
    inj = raw.get("injection") or {}
    out = raw.get("output") or {}
    enabled = dlp.get("enabled")
    return Policy(
        name=str(raw.get("name", Path(path).stem)),
        description=str(raw.get("description", "")),
        roles=roles,
        topics=topics,
        dlp_actions={str(k): str(v) for k, v in (dlp.get("actions") or {}).items()},
        dlp_default_action=str(dlp.get("default_action", "redact")),
        dlp_enabled=[str(x) for x in enabled] if enabled is not None else None,
        injection_warn=float(inj.get("warn_threshold", 0.4)),
        injection_block=float(inj.get("block_threshold", 0.7)),
        injection_use_classifier=bool(inj.get("llm_classifier", False)),
        injection_classifier_weight=float(inj.get("classifier_weight", 0.5)),
        output_leak_block=bool(out.get("block_on_prompt_leak", True)),
        output_overlap_threshold=float(out.get("prompt_overlap_threshold", 0.3)),
        output_secret_action=str(out.get("secret_action", "redact")),
        output_pii_action=str(out.get("pii_action", "redact")),
        output_sanitize_html=bool(out.get("sanitize_html", True)),
        output_allowed_image_hosts=[str(h) for h in out.get("allowed_image_hosts", []) or []],
        system_prompt=str(raw.get("system_prompt", "You are a helpful assistant.")).strip(),
        audit_path=str((raw.get("audit") or {}).get("path", "audit/audit.jsonl")),
        raw=raw,
    )


class PolicyEngine:
    """Evaluates requests; ``clock`` can be overridden for deterministic tests."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.clock: datetime | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        """Convenience loader."""
        return cls(load_policy(path))

    def now(self) -> datetime:
        """Current UTC time, or the fixed clock when one is set."""
        return self.clock or datetime.now(timezone.utc)

    def role(self, name: str) -> RolePolicy | None:
        """Role rules or None when the policy does not mention the role."""
        return self.policy.roles.get(name)

    # ------------------------------------------------------------ checks
    @staticmethod
    def _in_network(client_ip: str, networks: list[str]) -> bool:
        if not networks:
            return True
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)

    def _in_schedule(self, role: RolePolicy) -> bool:
        now = self.now()
        if role.days and DAY_NAMES[now.weekday()] not in role.days:
            return False
        if role.hours:
            start, end = role.hours
            minutes = now.hour * 60 + now.minute
            if start <= end:
                return start <= minutes < end
            return minutes >= start or minutes < end  # window crossing midnight
        return True

    def topics_in(self, role_name: str, text: str) -> list[str]:
        """Names of denied topics (for ``role_name``) that ``text`` matches."""
        role = self.role(role_name)
        if role is None:
            return []
        hits = []
        for tname in role.deny_topics:
            topic = self.policy.topics[tname]
            if topic.matches(text) >= topic.min_matches:
                hits.append(tname)
        return hits

    def evaluate(
        self,
        role_name: str,
        model: str,
        requested_tokens: int | None,
        tools: list[str],
        client_ip: str,
        user_text: str,
        message_count: int,
    ) -> Decision:
        """Run every policy check in order and return the first failure or an allow."""
        role = self.role(role_name)
        if role is None or not role.allow:
            return Decision(False, "role_denied", f"role {role_name!r} is not permitted to use the gateway", 403)
        if not self._in_network(client_ip, role.networks):
            return Decision(False, "network_denied", f"requests for role {role_name!r} are not accepted from {client_ip}", 403)
        if not self._in_schedule(role):
            return Decision(False, "outside_hours", f"role {role_name!r} may only use the gateway during its scheduled window", 403)
        if role.models and model not in role.models and "*" not in role.models:
            return Decision(False, "model_not_allowed", f"model {model!r} is not on the allowlist for role {role_name!r}", 403)
        if message_count > role.max_messages:
            return Decision(False, "too_many_messages", f"conversation exceeds {role.max_messages} messages", 413)
        if len(user_text) > role.max_input_chars:
            return Decision(False, "input_too_large", f"input exceeds {role.max_input_chars} characters", 413)
        disallowed = [t for t in tools if t not in role.tools]
        if disallowed:
            return Decision(False, "tool_not_allowed", f"tools not permitted for role {role_name!r}: {', '.join(disallowed)}", 403)
        topics = self.topics_in(role_name, user_text)
        if topics:
            return Decision(
                False,
                "topic_denied",
                f"content matches data class(es) not permitted for role {role_name!r}: {', '.join(topics)}",
                403,
                topics_hit=topics,
            )
        warnings: list[str] = []
        max_tokens = role.max_tokens
        if requested_tokens is not None and requested_tokens > role.max_tokens:
            warnings.append(f"max_tokens capped from {requested_tokens} to {role.max_tokens}")
        elif requested_tokens is not None:
            max_tokens = requested_tokens
        return Decision(
            True,
            "ok",
            "allowed",
            200,
            warnings=warnings,
            max_tokens=max_tokens,
            allowed_tools=list(role.tools),
            client_system_prompt_allowed=role.allow_client_system_prompt,
        )
