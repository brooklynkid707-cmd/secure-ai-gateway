"""Prompt-injection and jailbreak screening.

The screener is deliberately heuristic and transparent: every signal is a
named rule with a weight, and the final score is a noisy-OR combination
(``1 - prod(1 - w_i)``) so several weak signals add up without any single
keyword being decisive. Thresholds live in policy (``warn`` / ``block``).

Three channels are covered:

* **direct** - the user's own message (role ``user``)
* **indirect** - content the model is asked to *process* (role ``tool``,
  function results, or documents pasted inside ``<document>`` tags). Any
  instruction-like text here is a stronger signal, because a document should
  describe, not command. A multiplier is applied.
* **system** - client-supplied ``system`` messages. Those are only honoured
  for the ``admin`` role; everyone else gets them downgraded to ``user`` so the
  gateway's own system prompt (with its canary token) stays authoritative.

Obfuscation is handled by normalising the text first: zero-width characters
are stripped, leetspeak is folded (``1gn0r3`` -> ``ignore``), and base64 blobs
are decoded and rescanned. The optional LLM second-opinion classifier blends
its score in when policy enables it and the call succeeds.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from dataclasses import dataclass, field

from .llm_client import LLMClient


@dataclass(frozen=True)
class Rule:
    """A weighted heuristic signal."""

    name: str
    weight: float
    pattern: re.Pattern[str]
    description: str


def _r(name: str, weight: float, pattern: str, description: str) -> Rule:
    return Rule(name, weight, re.compile(pattern, re.IGNORECASE | re.DOTALL), description)


RULES: tuple[Rule, ...] = (
    _r("override_instructions", 0.75,
       r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}\b(instructions?|rules?|guidelines?|prompts?|directives?|restrictions?|policy|policies|constraints?)\b",
       "Explicit request to discard prior instructions"),
    _r("new_instructions", 0.55,
       r"\b(new|updated|real|actual|true|secret)\s+(instructions?|rules?|directives?|task|objective)\s*[:\-]",
       "Attempts to introduce replacement instructions"),
    _r("role_hijack", 0.6,
       r"\b(you are now|from now on you are|act as if you (are|were)|pretend (to be|you are)|you will now|your new (role|persona|identity) is|assume the role of)\b",
       "Persona / role override"),
    _r("developer_mode", 0.7,
       r"\b(developer mode|dan mode|do anything now|jailbreak|jailbroken|god mode|unrestricted mode|no restrictions mode|evil mode)\b",
       "Known jailbreak persona names"),
    _r("no_restrictions", 0.5,
       r"\b(without|no|free (of|from)|ignore)\s+(any\s+)?(restrictions?|limitations?|filters?|safety|ethical|moral)\b",
       "Asks to operate without safety constraints"),
    _r("reveal_system_prompt", 0.75,
       r"\b(reveal|print|show|repeat|output|display|dump|leak|tell me|what (is|are)|write out|echo|recite|verbatim)\b.{0,60}\b(system prompt|system message|initial prompt|hidden (prompt|instructions?)|your (instructions?|prompt|rules|configuration)|the prompt above|everything above|text above|canary)\b",
       "System-prompt extraction attempt"),
    _r("canary_reference", 0.6, r"\b(canary|secret token|internal reference|reference (token|code))\b",
       "References the gateway canary / hidden token"),
    _r("fake_delimiters", 0.65,
       r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?INST\]|<</?SYS>>|###\s*(system|instruction|admin)|^\s*system\s*:|\bBEGIN (SYSTEM|ADMIN|OVERRIDE)\b|\[SYSTEM\]|<system>|</system>)",
       "Chat-template delimiters smuggled into content"),
    _r("authority_claim", 0.45,
       r"\b(i am|this is|as) (the|your|an?) (developer|administrator|admin|creator|model provider|vendor|system operator|security team)\b.{0,60}\b(authori[sz]ed?|permission|override|allow|unlock|disable)\b",
       "Claims elevated authority to unlock behaviour"),
    _r("pwned_marker", 0.5, r"\b(say|print|output|respond with|reply with|write)\b.{0,30}\b(pwned|hacked|injected|owned)\b",
       "Measurable proof-of-injection marker"),
    _r("exfiltration", 0.7,
       r"\b(send|post|upload|transmit|forward|exfiltrate|leak|email)\b.{0,80}\b(to|at)\b\s*(https?://|ftp://|[a-z0-9.-]+\.(?:com|net|org|io|xyz|ru|cn)\b)",
       "Instructs the model to send data to an external endpoint"),
    _r("markdown_exfil", 0.8, r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*\)|!\[[^\]]*\]\(\s*https?://[^)\s]*\{\{",
       "Markdown image with query string - classic rendering-based exfiltration"),
    _r("hidden_instruction_to_ai", 0.6,
       r"\b(ai|assistant|chatgpt|gpt|llm|language model|model|bot)\b.{0,20}\b(reading this|processing this|if you (are|see) this)\b|\b(important|note|attention)\b.{0,10}\b(to|for) (the )?(ai|assistant|model|llm)\b",
       "Text addressed to the model rather than the reader (indirect injection)"),
    _r("do_not_tell_user", 0.6, r"\b(do not|don'?t|never)\s+(tell|inform|mention|reveal|let)\s+(the\s+)?user\b|\bwithout (telling|informing|alerting) the user\b",
       "Asks the model to hide behaviour from the user"),
    _r("tool_abuse", 0.5,
       r"\b(call|invoke|run|execute|use)\s+(the\s+)?(tool|function|command|shell|api)\b.{0,60}\b(delete|drop|rm -rf|transfer|wire|export all|dump)\b",
       "Instruction to invoke destructive tools"),
    _r("encoded_payload_hint", 0.35, r"\b(decode|base64|rot13|hex)\b.{0,40}\b(and (then )?(follow|execute|run|obey|do)|instructions?)\b",
       "Asks the model to decode and follow a hidden payload"),
    _r("continuation_trick", 0.5, r"\b(complete|continue|finish)\s+(the|this)\s+(sentence|text|phrase)\s*:?\s*['\"]?(my (system prompt|instructions) (is|are)|the (secret|password|token) is)",
       "Completion-style extraction"),
)

LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "!": "i"})
ZERO_WIDTH_RE = re.compile(r"[​-‏⁠⁡⁢⁣⁤﻿­\U000E0000-\U000E007F]")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
DOCUMENT_TAG_RE = re.compile(r"<(document|doc|file|email|webpage|tool_result|context)\b[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)

INDIRECT_MULTIPLIER = 1.35  # instruction-like text inside data is more suspicious


def normalise(text: str) -> str:
    """Unicode-fold, strip zero-width characters and collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    return re.sub(r"[ \t]+", " ", text)


def fold_leetspeak(text: str) -> str:
    """Map common leetspeak substitutions back to letters."""
    return text.translate(LEET_MAP)


def decode_base64_blobs(text: str) -> list[str]:
    """Return printable decodings of base64-looking blobs (ignores binary junk)."""
    decoded: list[str] = []
    for m in BASE64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and sum(c.isprintable() for c in s) / len(s) > 0.9:
            decoded.append(s)
    return decoded


@dataclass
class Signal:
    """One fired rule."""

    rule: str
    weight: float
    channel: str
    evidence: str


@dataclass
class ScreenResult:
    """Score plus explanation for one piece of content."""

    score: float
    signals: list[Signal] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    classifier_score: float | None = None
    classifier_reason: str = ""

    @property
    def rules(self) -> list[str]:
        """Names of all fired rules."""
        return sorted({s.rule for s in self.signals})


def noisy_or(weights: list[float]) -> float:
    """Combine independent evidence weights into one probability-like score."""
    if not weights:
        return 0.0
    log_miss = sum(math.log(max(1e-9, 1.0 - min(w, 0.999))) for w in weights)
    return round(1.0 - math.exp(log_miss), 4)


def _run_rules(text: str, channel: str, multiplier: float, tag: str) -> list[Signal]:
    signals: list[Signal] = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            evidence = m.group(0)[:80].replace("\n", " ")
            signals.append(Signal(f"{rule.name}{tag}", min(0.98, rule.weight * multiplier), channel, evidence))
    return signals


def screen_text(text: str, channel: str = "direct") -> ScreenResult:
    """Score a single string for injection signals (no LLM involved).

    Documents embedded in a direct message (``<document>``, ``<email>``, ...)
    are cut out and screened separately as *indirect* content.
    """
    multiplier = INDIRECT_MULTIPLIER if channel == "indirect" else 1.0
    obfuscation: list[str] = []
    norm = normalise(text)
    if norm != unicodedata.normalize("NFKC", text):
        obfuscation.append("zero_width_chars")

    embedded: list[str] = []
    if channel == "direct":
        embedded = [m.group(2) for m in DOCUMENT_TAG_RE.finditer(norm)]
        norm = DOCUMENT_TAG_RE.sub(" ", norm)

    signals = _run_rules(norm, channel, multiplier, "")

    leet = fold_leetspeak(norm)
    if leet != norm:
        leet_signals = _run_rules(leet, channel, multiplier, "")
        new = [s for s in leet_signals if s.rule not in {x.rule for x in signals}]
        if new:
            obfuscation.append("leetspeak")
            signals.extend(Signal(s.rule + "(leet)", s.weight, channel, s.evidence) for s in new)

    for blob in decode_base64_blobs(norm):
        b64_signals = _run_rules(normalise(blob), channel, multiplier, "(base64)")
        if b64_signals:
            obfuscation.append("base64")
            signals.extend(b64_signals)
            signals.append(Signal("encoded_instruction", 0.5, channel, blob[:60]))

    for inner_text in embedded:
        inner = screen_text(inner_text, "indirect")
        signals.extend(inner.signals)
        obfuscation.extend(o for o in inner.obfuscation if o not in obfuscation)

    return ScreenResult(noisy_or([s.weight for s in signals]), signals, obfuscation)


def screen_messages(
    messages: list[dict],
    client: LLMClient | None = None,
    use_classifier: bool = False,
    classifier_weight: float = 0.5,
) -> ScreenResult:
    """Screen every user/tool message and return the combined worst-case result."""
    combined = ScreenResult(0.0)
    worst_text = ""
    worst = 0.0
    for msg in messages:
        role = str(msg.get("role", "user"))
        content = _content_text(msg.get("content"))
        if not content:
            continue
        channel = "indirect" if role in {"tool", "function"} else "direct"
        res = screen_text(content, channel)
        combined.signals.extend(res.signals)
        combined.obfuscation.extend(o for o in res.obfuscation if o not in combined.obfuscation)
        if res.score > worst:
            worst, worst_text = res.score, content
    combined.score = noisy_or([s.weight for s in combined.signals])

    if use_classifier and client is not None and (worst_text or messages):
        target = worst_text or _content_text(messages[-1].get("content"))
        verdict = client.classify_injection(target)
        if verdict.available:
            combined.classifier_score = verdict.score
            combined.classifier_reason = verdict.reason
            combined.score = round(
                (1 - classifier_weight) * combined.score + classifier_weight * verdict.score, 4
            )
    return combined


def _content_text(content: object) -> str:
    """Flatten OpenAI-style content (string or list of parts) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(str(part.get("text", "")))
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return ""
