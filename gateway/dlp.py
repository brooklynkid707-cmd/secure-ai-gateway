"""Data-loss prevention: find PII and secrets in text and redact them reversibly.

Each detector is a named regex plus an optional validator (for example a Luhn
check for card numbers so that random 16-digit strings are not flagged). A
scan produces ``Finding`` objects; ``redact`` replaces each finding with a
placeholder such as ``[[EMAIL_1]]`` and returns a ``RedactionMap`` so the
original values can be restored in the *response* path - the model never sees
the real value, but the user still gets a coherent answer.

Per-detector actions come from policy:

* ``redact`` - replace and continue (default)
* ``block``  - refuse the request (used for private keys and cloud credentials)
* ``warn``   - leave the text alone, annotate the response and audit record
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

Validator = Callable[[str], bool]


def luhn_valid(number: str) -> bool:
    """Return True when ``number`` (digits, spaces or dashes) passes the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ssn_valid(value: str) -> bool:
    area, group, serial = re.split(r"[-\s]", value)
    return area not in {"000", "666"} and not area.startswith("9") and group != "00" and serial != "0000"


def _jwt_valid(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(len(p) >= 8 for p in parts[:2])


@dataclass(frozen=True)
class Detector:
    """A named pattern with a severity and optional validator."""

    name: str
    pattern: re.Pattern[str]
    kind: str  # "pii" | "secret"
    validator: Validator | None = None

    def finditer(self, text: str) -> Iterable[re.Match[str]]:
        """Yield validated matches."""
        for match in self.pattern.finditer(text):
            value = match.group(0)
            if self.validator is None or self.validator(value):
                yield match


DETECTORS: tuple[Detector, ...] = (
    Detector(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        "secret",
    ),
    Detector("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "secret"),
    Detector(
        "aws_secret_key",
        re.compile(r"(?i)aws[_\-\s]?(?:secret|secret_access)[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"),
        "secret",
    ),
    Detector("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "secret"),
    Detector("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", re.IGNORECASE), "secret"),
    Detector("openai_style_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"), "secret"),
    Detector("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "secret", _jwt_valid),
    Detector(
        "generic_api_key",
        re.compile(r"(?i)(?<![a-z])(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"),
        "secret",
    ),
    Detector(
        "password_assignment",
        re.compile(r"(?i)(?<![a-z])(?:password|passwd|pwd)\s*[:=]\s*['\"]?(\S{6,})"),
        "secret",
    ),
    Detector("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), "pii", luhn_valid),
    Detector("ssn", re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"), "pii", _ssn_valid),
    Detector("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "pii"),
    Detector(
        "phone",
        re.compile(r"(?<![\w.])(?:\+?1[ -.])?(?:\(\d{3}\)|\d{3})[ -.]\d{3}[ -.]\d{4}\b"),
        "pii",
    ),
    Detector("ipv4_private", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), "pii"),
)

DETECTOR_NAMES = tuple(d.name for d in DETECTORS)
PLACEHOLDER_RE = re.compile(r"\[\[([A-Z_]+)_(\d+)\]\]")


@dataclass
class Finding:
    """One detected PII/secret span."""

    detector: str
    kind: str
    start: int
    end: int
    value: str

    @property
    def preview(self) -> str:
        """Masked preview safe for logs (first 2 and last 2 characters)."""
        v = self.value.replace("\n", " ")
        if len(v) <= 6:
            return "*" * len(v)
        return f"{v[:2]}{'*' * min(len(v) - 4, 12)}{v[-2:]}"


@dataclass
class RedactionMap:
    """Placeholder -> original value mapping for one request."""

    placeholders: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def placeholder_for(self, detector: str, value: str) -> str:
        """Return a stable placeholder for ``value`` (same value -> same placeholder)."""
        for ph, original in self.placeholders.items():
            if original == value and ph.startswith(f"[[{detector.upper()}_"):
                return ph
        n = self.counters.get(detector, 0) + 1
        self.counters[detector] = n
        ph = f"[[{detector.upper()}_{n}]]"
        self.placeholders[ph] = value
        return ph

    def restore(self, text: str) -> str:
        """Replace placeholders in ``text`` with the original values."""
        if not self.placeholders:
            return text

        def _sub(m: re.Match[str]) -> str:
            return self.placeholders.get(m.group(0), m.group(0))

        return PLACEHOLDER_RE.sub(_sub, text)

    def __len__(self) -> int:
        return len(self.placeholders)


def scan(text: str, enabled: Iterable[str] | None = None) -> list[Finding]:
    """Scan ``text`` with every (or the given) detector; overlapping spans keep the earliest/longest."""
    names = set(enabled) if enabled is not None else set(DETECTOR_NAMES)
    found: list[Finding] = []
    for det in DETECTORS:
        if det.name not in names:
            continue
        for m in det.finditer(text):
            found.append(Finding(det.name, det.kind, m.start(), m.end(), m.group(0)))
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    last_end = -1
    for f in found:
        if f.start < last_end:
            continue
        merged.append(f)
        last_end = f.end
    return merged


@dataclass
class DLPResult:
    """Outcome of screening a piece of text."""

    text: str
    findings: list[Finding]
    blocked_by: list[str]
    warned: list[str]
    redacted: list[str]


def apply(
    text: str,
    actions: dict[str, str],
    default_action: str = "redact",
    redaction_map: RedactionMap | None = None,
    enabled: Iterable[str] | None = None,
) -> DLPResult:
    """Scan and apply per-detector actions, returning the transformed text and what happened."""
    rmap = redaction_map if redaction_map is not None else RedactionMap()
    findings = scan(text, enabled)
    blocked: list[str] = []
    warned: list[str] = []
    redacted: list[str] = []
    out: list[str] = []
    cursor = 0
    for f in findings:
        action = actions.get(f.detector, default_action)
        if action == "block":
            blocked.append(f.detector)
            continue
        if action == "warn":
            warned.append(f.detector)
            continue
        if action == "ignore":
            continue
        out.append(text[cursor : f.start])
        out.append(rmap.placeholder_for(f.detector, f.value))
        redacted.append(f.detector)
        cursor = f.end
    out.append(text[cursor:])
    new_text = "".join(out) if not blocked else text
    return DLPResult(new_text, findings, blocked, warned, redacted)
