"""Replay the attack corpus through a live gateway and print a pass/fail matrix.

By default the selftest starts the mock upstream and the gateway in-process on
loopback ports, pins the policy clock to a weekday afternoon (so time-of-day
rules are deterministic) and replays every case under ``tests/attack_corpus``.
With ``--url`` it targets an already-running gateway instead; cases that need
the pinned clock are skipped there.

Corpus case format::

    - id: inj-001
      category: injection
      title: Classic instruction override
      identity: analyst            # viewer | analyst | admin | burst | budget | partner | revoked | none | bogus
      request: {model: mock-gpt, messages: [...]}
      repeat: 1                    # optional; send N times, evaluate the LAST reply
      clock: "2026-10-23T03:00:00Z"  # optional; pin the policy clock for this case
      expect:
        status: 403
        code: injection_blocked
        decision: block
        actions_include: [dlp_redact]
        response_contains: "..."
        response_not_contains: "..."
        min_injection_score: 0.4
        any_status: 429            # with repeat: pass if ANY reply had this status
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

DEMO_KEYS = {
    "viewer": "sag-viewer-demo-key-0001",
    "analyst": "sag-analyst-demo-key-0002",
    "admin": "sag-admin-demo-key-0003",
    "burst": "sag-burst-demo-key-0004",
    "budget": "sag-budget-demo-key-0005",
    "partner": "sag-partner-demo-key-0006",
    "revoked": "sag-revoked-demo-key-0007",
    "bogus": "sag-not-a-real-key-9999",
    "none": "",
}

PINNED_CLOCK = datetime(2026, 10, 23, 14, 0, tzinfo=timezone.utc)  # Friday 14:00 UTC
CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "attack_corpus"


@dataclass
class Case:
    """One corpus entry."""

    id: str
    category: str
    title: str
    identity: str
    request: dict[str, Any]
    expect: dict[str, Any]
    repeat: int = 1
    clock: str | None = None
    source: str = ""


@dataclass
class CaseResult:
    """Outcome for one case."""

    case: Case
    passed: bool
    observed: str
    detail: str = ""
    skipped: bool = False


@dataclass
class Reply:
    """A raw HTTP reply."""

    status: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """Assistant content or error message."""
        if "choices" in self.body:
            return str(((self.body["choices"] or [{}])[0].get("message") or {}).get("content") or "")
        return str((self.body.get("error") or {}).get("message", ""))


def load_corpus(directory: Path = CORPUS_DIR) -> list[Case]:
    """Read every ``*.yaml`` in the corpus directory."""
    cases: list[Case] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in data.get("cases", []):
            cid = str(raw["id"])
            if cid in seen:
                raise ValueError(f"duplicate case id {cid} in {path.name}")
            seen.add(cid)
            cases.append(
                Case(
                    id=cid,
                    category=str(raw.get("category", "uncategorised")),
                    title=str(raw.get("title", "")),
                    identity=str(raw.get("identity", "analyst")),
                    request=dict(raw.get("request") or {}),
                    expect=dict(raw.get("expect") or {}),
                    repeat=int(raw.get("repeat", 1)),
                    clock=raw.get("clock"),
                    source=path.name,
                )
            )
    return cases


def materialise(request: dict[str, Any]) -> dict[str, Any]:
    """Expand ``generate`` shortcuts into real messages (keeps the corpus readable)."""
    req = dict(request)
    gen = req.pop("generate", None)
    if gen:
        if "long_text_chars" in gen:
            unit = "The quick brown fox jumps over the lazy dog. "
            text = (unit * (int(gen["long_text_chars"]) // len(unit) + 1))[: int(gen["long_text_chars"])]
            req["messages"] = [{"role": "user", "content": "Summarize: " + text}]
        elif "message_count" in gen:
            n = int(gen["message_count"])
            req["messages"] = [{"role": "user" if i % 2 == 0 else "assistant", "content": f"turn {i}"} for i in range(n)]
    return req


def post_chat(base_url: str, key: str, payload: dict[str, Any], timeout: float = 15.0) -> Reply:
    """POST to the gateway and capture status, JSON body and headers."""
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/v1/chat/completions", data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - loopback/operator URL
            return Reply(resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": {"message": raw[:200]}}
        return Reply(exc.code, body, dict(exc.headers))


def evaluate(case: Case, replies: list[Reply]) -> CaseResult:
    """Compare the last reply (and, for ``any_status``, all replies) with expectations."""
    last = replies[-1]
    exp = case.expect
    failures: list[str] = []
    code = last.headers.get("X-Gateway-Code") or (last.body.get("error") or {}).get("code", "")
    decision = last.headers.get("X-Gateway-Decision", "")
    actions = set(filter(None, last.headers.get("X-Gateway-Actions", "").split(",")))
    score = float(last.headers.get("X-Gateway-Injection-Score", "0") or 0)

    if "any_status" in exp:
        if not any(r.status == exp["any_status"] for r in replies):
            failures.append(f"no reply had status {exp['any_status']} (got {[r.status for r in replies]})")
    if "status" in exp and last.status != exp["status"]:
        failures.append(f"status {last.status} != {exp['status']}")
    if "code" in exp and code != exp["code"]:
        failures.append(f"code {code!r} != {exp['code']!r}")
    if "decision" in exp and decision != exp["decision"]:
        failures.append(f"decision {decision!r} != {exp['decision']!r}")
    for a in exp.get("actions_include", []) or []:
        if a not in actions:
            failures.append(f"action {a!r} missing from {sorted(actions)}")
    for a in exp.get("actions_exclude", []) or []:
        if a in actions:
            failures.append(f"action {a!r} unexpectedly present")
    if "response_contains" in exp and exp["response_contains"] not in last.text:
        failures.append(f"response lacks {exp['response_contains']!r}")
    if "response_not_contains" in exp and exp["response_not_contains"] in last.text:
        failures.append(f"response contains forbidden {exp['response_not_contains']!r}")
    if "min_injection_score" in exp and score < float(exp["min_injection_score"]):
        failures.append(f"injection score {score:.2f} < {exp['min_injection_score']}")
    if "max_injection_score" in exp and score > float(exp["max_injection_score"]):
        failures.append(f"injection score {score:.2f} > {exp['max_injection_score']}")

    observed = f"{last.status} {code or decision or '-'}"
    if actions:
        observed += " [" + ",".join(sorted(actions)) + "]"
    return CaseResult(case, not failures, observed, "; ".join(failures))


class InProcessGateway:
    """Mock upstream + gateway served from background threads."""

    def __init__(self, policy_path: str, identities_path: str, audit_path: str) -> None:
        import logging

        from werkzeug.serving import make_server

        from .mock_llm import MockServer
        from .server import GatewaySettings, create_app

        self.mock = MockServer().start()
        settings = GatewaySettings(policy_path=policy_path, identities_path=identities_path, upstream_url=self.mock.url, audit_path=audit_path)
        self.app = create_app(settings)
        self.gateway = self.app.extensions["gateway"]
        self.gateway.policy_engine.clock = PINNED_CLOCK
        logging.getLogger("werkzeug").setLevel(logging.ERROR)  # keep the matrix readable
        self.server = make_server("127.0.0.1", 0, self.app, threaded=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def set_clock(self, iso: str | None) -> None:
        """Pin the policy clock (``None`` restores the default pinned afternoon)."""
        if iso is None:
            self.gateway.policy_engine.clock = PINNED_CLOCK
        else:
            self.gateway.policy_engine.clock = datetime.fromisoformat(iso.replace("Z", "+00:00"))

    def close(self) -> None:
        """Stop both servers."""
        self.server.shutdown()
        self.mock.stop()


def run_selftest(
    policy_path: str,
    identities_path: str,
    url: str | None = None,
    audit_path: str | None = None,
    corpus_dir: Path = CORPUS_DIR,
    only_category: str | None = None,
    verbose: bool = False,
) -> tuple[list[CaseResult], str | None]:
    """Execute the corpus and return results plus the audit path used (in-process mode)."""
    cases = load_corpus(corpus_dir)
    if only_category:
        cases = [c for c in cases if c.category == only_category]
    local: InProcessGateway | None = None
    if url is None:
        audit_path = audit_path or f"audit/selftest-{int(time.time())}.jsonl"
        local = InProcessGateway(policy_path, identities_path, audit_path)
        url = local.url
    results: list[CaseResult] = []
    try:
        for case in cases:
            if case.clock and local is None:
                results.append(CaseResult(case, True, "skipped", "needs pinned clock (in-process mode only)", skipped=True))
                continue
            if local is not None:
                local.set_clock(case.clock)
                if case.category != "rate_limit":
                    local.gateway.auth.reset()  # quota cases own their state; others start fresh
            key = DEMO_KEYS.get(case.identity, case.identity)
            payload = materialise(case.request)
            replies = [post_chat(url, key, payload) for _ in range(max(1, case.repeat))]
            res = evaluate(case, replies)
            results.append(res)
            if verbose and not res.passed:
                print(f"  {case.id}: {res.detail}\n    last body: {json.dumps(replies[-1].body)[:400]}", file=sys.stderr)
        if local is not None:
            local.set_clock(None)
    finally:
        if local is not None:
            local.close()
    return results, audit_path if local is not None else None


def format_matrix(results: list[CaseResult]) -> str:
    """Render the pass/fail matrix and a per-category summary."""
    rows = [("ID", "CATEGORY", "IDENTITY", "EXPECTED", "OBSERVED", "RESULT")]
    for r in results:
        exp = r.case.expect
        expected = " ".join(
            str(v) for v in (exp.get("status"), exp.get("code") or exp.get("decision"), f"any={exp['any_status']}" if "any_status" in exp else None) if v
        )
        if exp.get("actions_include"):
            expected += " [" + ",".join(exp["actions_include"]) + "]"
        status = "SKIP" if r.skipped else ("PASS" if r.passed else "FAIL")
        rows.append((r.case.id, r.case.category, r.case.identity, expected, r.observed, status))
    widths = [min(max(len(row[i]) for row in rows), 44) for i in range(6)]
    lines = []
    for n, row in enumerate(rows):
        lines.append("  ".join(cell[: widths[i]].ljust(widths[i]) for i, cell in enumerate(row)))
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    lines.append("")
    cats: dict[str, list[int]] = {}
    for r in results:
        bucket = cats.setdefault(r.case.category, [0, 0, 0])
        bucket[2 if r.skipped else (0 if r.passed else 1)] += 1
    lines.append(f"{'CATEGORY':<18}{'PASS':>6}{'FAIL':>6}{'SKIP':>6}")
    for cat, (p, f, s) in sorted(cats.items()):
        lines.append(f"{cat:<18}{p:>6}{f:>6}{s:>6}")
    total_p = sum(1 for r in results if r.passed and not r.skipped)
    total_f = sum(1 for r in results if not r.passed)
    total_s = sum(1 for r in results if r.skipped)
    lines.append(f"{'TOTAL':<18}{total_p:>6}{total_f:>6}{total_s:>6}")
    failed = [r for r in results if not r.passed]
    if failed:
        lines.append("")
        lines.append("Failures:")
        for r in failed:
            lines.append(f"  {r.case.id}: {r.detail}")
    return "\n".join(lines)
