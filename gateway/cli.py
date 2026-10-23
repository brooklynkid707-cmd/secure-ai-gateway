"""Command-line interface: ``python -m gateway <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = str(ROOT / "config" / "balanced.yaml")
DEFAULT_IDENTITIES = str(ROOT / "config" / "identities.yaml")


def _cmd_run(args: argparse.Namespace) -> int:
    from .mock_llm import MockServer
    from .server import GatewaySettings, create_app

    upstream = args.upstream or os.environ.get("AISEC_LLM_URL") or "mock"
    mock: MockServer | None = None
    if upstream == "mock":
        mock = MockServer().start()
        upstream = mock.url
        print(f"[gateway] started bundled mock upstream at {upstream}")
    settings = GatewaySettings(
        policy_path=args.policy,
        identities_path=args.identities,
        upstream_url=upstream,
        audit_path=args.audit,
        trust_proxy_headers=args.trust_proxy,
        upstream_timeout=args.timeout,
    )
    app = create_app(settings)
    gw = app.extensions["gateway"]
    print(f"[gateway] policy={gw.policy.name} identities={len(gw.auth.identities())} audit={gw.audit.path}")
    print(f"[gateway] listening on http://{args.host}:{args.port}  (POST /v1/chat/completions)")
    try:
        app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    finally:
        if mock is not None:
            mock.stop()
    return 0


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .selftest import format_matrix, run_selftest

    results, audit_path = run_selftest(
        args.policy, args.identities, url=args.url, audit_path=args.audit,
        corpus_dir=Path(args.corpus), only_category=args.category, verbose=args.verbose,
    )
    print(format_matrix(results))
    if audit_path:
        from .audit import verify

        v = verify(audit_path)
        print(f"\naudit chain: {audit_path} -> {v.records} records, {'intact' if v.ok else 'BROKEN: ' + v.reason}")
    failed = sum(1 for r in results if not r.passed)
    return 1 if failed else 0


def _cmd_replay(args: argparse.Namespace) -> int:
    from collections import Counter

    from .selftest import DEMO_KEYS, InProcessGateway, post_chat

    rows = [json.loads(line) for line in Path(args.file).read_text(encoding="utf-8").splitlines() if line.strip()]
    local: InProcessGateway | None = None
    url = args.url
    if url is None:
        local = InProcessGateway(args.policy, args.identities, args.audit or f"audit/replay-{Path(args.file).stem}.jsonl")
        url = local.url
    outcomes: Counter[tuple[str, str]] = Counter()
    try:
        for row in rows:
            if local is not None:
                local.gateway.auth.reset()
            key = DEMO_KEYS.get(row.get("identity", "analyst"), row.get("identity", ""))
            reply = post_chat(url, key, row["request"])
            code = reply.headers.get("X-Gateway-Code") or (reply.body.get("error") or {}).get("code", "?")
            actions = reply.headers.get("X-Gateway-Actions", "")
            outcomes[(row.get("label", "?"), code)] += 1
            if not args.quiet:
                print(f"{row.get('seq', '-'):>4}  {row.get('identity', '?'):<8} {row.get('label', '?'):<12} -> {reply.status} {code:<20} {actions}")
    finally:
        if local is not None:
            local.close()
    print()
    print(f"{'LABEL':<13}{'GATEWAY CODE':<22}{'COUNT':>6}")
    for (label, code), n in sorted(outcomes.items()):
        print(f"{label:<13}{code:<22}{n:>6}")
    if local is not None:
        print(f"\naudit log: {local.gateway.audit.path}")
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    from .audit import verify

    v = verify(args.path)
    if v.ok:
        print(f"OK: {v.records} records, chain intact ({args.path})")
        return 0
    print(f"TAMPERED: chain broken at seq {v.first_bad_seq} after {v.records} records - {v.reason}")
    return 2


def _cmd_redact_test(args: argparse.Namespace) -> int:
    from . import dlp
    from .policy import load_policy

    policy = load_policy(args.policy)
    text = Path(args.file).read_text(encoding="utf-8") if args.file else " ".join(args.text)
    rmap = dlp.RedactionMap()
    res = dlp.apply(text, policy.dlp_actions, policy.dlp_default_action, rmap, policy.dlp_enabled)
    print(f"policy: {policy.name}")
    print(f"findings: {len(res.findings)}")
    for f in res.findings:
        action = policy.dlp_actions.get(f.detector, policy.dlp_default_action)
        print(f"  {f.detector:<20} {f.kind:<6} action={action:<6} preview={f.preview}")
    if res.blocked_by:
        print("DECISION: BLOCK (" + ", ".join(sorted(set(res.blocked_by))) + ")")
        return 1
    print("DECISION: ALLOW" + (" with redaction" if res.redacted else "") + (" with warnings" if res.warned else ""))
    print("--- redacted text ---")
    print(res.text)
    if rmap.placeholders and args.show_map:
        print("--- placeholder map (kept in memory per request, never logged) ---")
        for ph, original in rmap.placeholders.items():
            print(f"  {ph} -> {original}")
    return 0


def _cmd_screen_test(args: argparse.Namespace) -> int:
    from .injection import screen_text
    from .policy import load_policy

    policy = load_policy(args.policy)
    text = Path(args.file).read_text(encoding="utf-8") if args.file else " ".join(args.text)
    res = screen_text(text, args.channel)
    verdict = "BLOCK" if res.score >= policy.injection_block else "WARN" if res.score >= policy.injection_warn else "CLEAN"
    print(f"score={res.score:.2f} verdict={verdict} (warn>={policy.injection_warn}, block>={policy.injection_block})")
    if res.obfuscation:
        print("obfuscation: " + ", ".join(res.obfuscation))
    for s in res.signals:
        print(f"  {s.rule:<32} w={s.weight:.2f} {s.channel:<8} {s.evidence!r}")
    return 0


def _cmd_hash_key(args: argparse.Namespace) -> int:
    from .auth import hash_key

    key = args.key or getpass.getpass("API key (not echoed): ")
    print(hash_key(key))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Argument parser for all sub-commands."""
    p = argparse.ArgumentParser(prog="python -m gateway", description="Secure AI Gateway - policy-enforcing LLM reverse proxy")
    p.add_argument("--version", action="version", version=f"secure-ai-gateway {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--policy", default=DEFAULT_POLICY, help="policy YAML (default: config/balanced.yaml)")
        sp.add_argument("--identities", default=DEFAULT_IDENTITIES, help="identities YAML")

    run = sub.add_parser("run", help="serve the gateway")
    common(run)
    run.add_argument("--upstream", default=None, help="upstream chat-completions URL, or 'mock' (default: $AISEC_LLM_URL or mock)")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    run.add_argument("--audit", default=None, help="override audit log path")
    run.add_argument("--timeout", type=float, default=30.0, help="upstream timeout seconds")
    run.add_argument("--trust-proxy", action="store_true", help="honour X-Forwarded-For (only behind a trusted proxy)")
    run.set_defaults(func=_cmd_run)

    st = sub.add_parser("selftest", help="replay the attack corpus and print a pass/fail matrix")
    common(st)
    st.add_argument("--url", default=None, help="target an already running gateway instead of in-process")
    st.add_argument("--corpus", default=str(ROOT / "tests" / "attack_corpus"))
    st.add_argument("--category", default=None, help="only run one category")
    st.add_argument("--audit", default=None, help="audit log path for the in-process run")
    st.add_argument("--verbose", action="store_true", help="print failing replies")
    st.set_defaults(func=_cmd_selftest)

    rp = sub.add_parser("replay", help="replay a JSONL traffic file (see scripts/generate_sample_data.py)")
    common(rp)
    rp.add_argument("file")
    rp.add_argument("--url", default=None, help="target a running gateway instead of in-process")
    rp.add_argument("--audit", default=None)
    rp.add_argument("--quiet", action="store_true", help="summary only")
    rp.set_defaults(func=_cmd_replay)

    va = sub.add_parser("verify-audit", help="verify the hash chain of an audit JSONL file")
    va.add_argument("path", nargs="?", default="audit/audit.jsonl")
    va.set_defaults(func=_cmd_verify_audit)

    rt = sub.add_parser("redact-test", help="run the DLP engine over text and show the result")
    common(rt)
    rt.add_argument("text", nargs="*")
    rt.add_argument("--file", default=None)
    rt.add_argument("--show-map", action="store_true", help="print the placeholder -> original map")
    rt.set_defaults(func=_cmd_redact_test)

    sc = sub.add_parser("screen-test", help="score text with the injection screener")
    common(sc)
    sc.add_argument("text", nargs="*")
    sc.add_argument("--file", default=None)
    sc.add_argument("--channel", choices=["direct", "indirect"], default="direct")
    sc.set_defaults(func=_cmd_screen_test)

    hk = sub.add_parser("hash-key", help="print the sha256 digest to store in identities.yaml")
    hk.add_argument("key", nargs="?", default=None, help="key (prompted securely when omitted)")
    hk.set_defaults(func=_cmd_hash_key)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
