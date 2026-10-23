"""Response-path controls: leak detection, secret re-scan, sanitisation, tool allowlist.

The upstream model is treated as an untrusted component. Its output is checked
for:

1. **System-prompt leakage** - the exact canary token, or a high n-gram
   overlap with the gateway system prompt (the model paraphrasing it).
2. **Secrets / PII** - the same DLP detectors as the request path. A model can
   regurgitate training data or content from a tool result.
3. **Insecure output handling** - ``<script>``, event handlers,
   ``javascript:`` URLs, iframes and Markdown images pointing at non-allowlisted
   hosts (an exfiltration channel when the client renders Markdown).
4. **Tool calls** - any ``tool_calls`` the model emits are checked against the
   role's allowlist; disallowed calls are stripped and the response is marked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from . import dlp

SCRIPT_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>|<\s*script\b[^>]*/?>", re.IGNORECASE | re.DOTALL)
IFRAME_RE = re.compile(r"<\s*(iframe|object|embed|form|meta|link|base)\b[^>]*>(.*?<\s*/\s*\1\s*>)?", re.IGNORECASE | re.DOTALL)
EVENT_ATTR_RE = re.compile(r"\s(on[a-z]+)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
JS_URL_RE = re.compile(r"(href|src|action|formaction|xlink:href)\s*=\s*([\"']?)\s*(javascript|vbscript|data):[^\"'>\s]*\2", re.IGNORECASE)
MD_LINK_RE = re.compile(r"(!?)\[([^\]]*)\]\(\s*(?:javascript|vbscript|data):[^)]*\)", re.IGNORECASE)
MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(\s*(https?://[^)\s]+)\s*\)", re.IGNORECASE)
HTML_IMG_RE = re.compile(r"<\s*img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)[^>]*>", re.IGNORECASE)
WORD_RE = re.compile(r"[a-z0-9]+")


def _ngrams(text: str, n: int = 8) -> set[tuple[str, ...]]:
    words = WORD_RE.findall(text.lower())
    return {tuple(words[i : i + n]) for i in range(max(0, len(words) - n + 1))}


def prompt_overlap(system_prompt: str, output: str, n: int = 8) -> float:
    """Fraction of the system prompt's word n-grams that appear verbatim in ``output``."""
    ref = _ngrams(system_prompt, n)
    if not ref:
        return 0.0
    hit = len(ref & _ngrams(output, n))
    return round(hit / len(ref), 3)


@dataclass
class GuardConfig:
    """Output-guard settings taken from policy."""

    canary: str = ""
    system_prompt: str = ""
    overlap_threshold: float = 0.3
    block_on_leak: bool = True
    secret_action: str = "redact"  # redact | block | warn
    pii_action: str = "redact"
    sanitize_html: bool = True
    allowed_image_hosts: list[str] = field(default_factory=list)
    allowed_tools: list[str] | None = None  # None -> no tool calls allowed at all
    dlp_enabled: list[str] | None = None
    detector_actions: dict[str, str] = field(default_factory=dict)  # inbound actions; warn/ignore carry over

    def action_for(self, detector: str, kind: str) -> str:
        """Output action for one detector: inbound warn/ignore is honoured, otherwise the kind default."""
        inbound = self.detector_actions.get(detector, "")
        if inbound in ("warn", "ignore"):
            return inbound
        return self.secret_action if kind == "secret" else self.pii_action


@dataclass
class GuardResult:
    """What the guard did to a response."""

    blocked: bool = False
    block_code: str = ""
    block_message: str = ""
    actions: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    dropped_tool_calls: list[str] = field(default_factory=list)
    overlap: float = 0.0


def sanitize_markup(text: str, allowed_image_hosts: list[str]) -> tuple[str, list[str]]:
    """Strip active content and off-allowlist images from model output."""
    actions: list[str] = []
    new, n = SCRIPT_RE.subn("[removed: script]", text)
    if n:
        actions.append("script_removed")
    new, n = IFRAME_RE.subn("[removed: embedded element]", new)
    if n:
        actions.append("embed_removed")
    new, n = EVENT_ATTR_RE.subn("", new)
    if n:
        actions.append("event_handler_removed")
    new, n = JS_URL_RE.subn(r"\1=\2#blocked\2", new)
    if n:
        actions.append("js_url_removed")
    new, n = MD_LINK_RE.subn(r"[\2](#blocked)", new)
    if n:
        actions.append("js_url_removed")

    def _img(m: re.Match[str], raw: bool) -> str:
        url = m.group(2) if not raw else m.group(1)
        host = (urlparse(url).hostname or "").lower()
        if host and any(host == h or host.endswith("." + h) for h in allowed_image_hosts):
            return m.group(0)
        actions.append("external_image_removed")
        alt = m.group(1) if not raw else "image"
        return f"[removed: external image {alt!r}]"

    new = MD_IMAGE_RE.sub(lambda m: _img(m, False), new)
    new = HTML_IMG_RE.sub(lambda m: _img(m, True), new)
    return new, sorted(set(actions))


def guard_response(
    response: dict[str, Any],
    cfg: GuardConfig,
    redaction_map: dlp.RedactionMap | None = None,
) -> GuardResult:
    """Apply all output controls to an OpenAI-style response **in place**."""
    result = GuardResult()
    choices = response.get("choices") or []
    for choice in choices:
        message = choice.get("message") or {}
        content = message.get("content")
        text = content if isinstance(content, str) else ""

        # 1. canary / prompt leak ---------------------------------------
        if cfg.canary and cfg.canary in text:
            result.findings.append("canary_token")
        if cfg.system_prompt:
            result.overlap = max(result.overlap, prompt_overlap(cfg.system_prompt, text))
            if result.overlap >= cfg.overlap_threshold:
                result.findings.append("system_prompt_overlap")
        if ("canary_token" in result.findings or "system_prompt_overlap" in result.findings) and cfg.block_on_leak:
            result.blocked = True
            result.block_code = "system_prompt_leak"
            result.block_message = "response withheld: it would have disclosed the gateway system prompt"
            result.actions.append("output_blocked")
            message["content"] = ""
            continue

        # 2. secrets / PII re-scan ----------------------------------------
        findings = dlp.scan(text, cfg.dlp_enabled)
        if findings:
            actions = {f.detector: cfg.action_for(f.detector, f.kind) for f in findings}
            result.findings.extend(sorted({f.detector for f in findings}))
            if any(a == "block" for a in actions.values()):
                result.blocked = True
                result.block_code = "output_secret"
                result.block_message = "response withheld: it contained credential or personal data"
                result.actions.append("output_blocked")
                message["content"] = ""
                continue
            # Placeholders we injected ourselves are restored, never re-redacted.
            scratch = dlp.RedactionMap()
            res = dlp.apply(text, actions, "redact", scratch, cfg.dlp_enabled)
            if res.redacted:
                text = res.text
                result.actions.append("output_redacted")
            if res.warned:
                result.actions.append("output_warned")

        # 3. markup sanitisation -----------------------------------------
        if cfg.sanitize_html and text:
            text, actions = sanitize_markup(text, cfg.allowed_image_hosts)
            if actions:
                result.actions.extend(actions)
                result.actions.append("output_sanitized")

        # 4. restore placeholders the request path inserted ---------------
        if redaction_map is not None and len(redaction_map):
            restored = redaction_map.restore(text)
            if restored != text:
                result.actions.append("placeholders_restored")
            text = restored
        if isinstance(content, str):
            message["content"] = text

        # 5. tool-call allowlist -------------------------------------------
        calls = message.get("tool_calls") or []
        if calls:
            kept = []
            for call in calls:
                name = str(((call.get("function") or {}).get("name")) or call.get("name") or "")
                if cfg.allowed_tools is not None and name in cfg.allowed_tools:
                    kept.append(call)
                else:
                    result.dropped_tool_calls.append(name or "<unnamed>")
            if result.dropped_tool_calls:
                result.actions.append("tool_call_dropped")
                message["tool_calls"] = kept
                if not kept:
                    message.pop("tool_calls", None)
                    choice["finish_reason"] = "stop"
                    if not message.get("content"):
                        message["content"] = (
                            "[gateway] the model attempted to call a tool that is not permitted for your role: "
                            + ", ".join(result.dropped_tool_calls)
                        )
    result.actions = sorted(set(result.actions))
    return result
