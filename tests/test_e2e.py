"""End-to-end over real HTTP: mock upstream and gateway on loopback ports, stdlib client."""

from __future__ import annotations

import json
import urllib.request

import pytest

from gateway import audit
from gateway.selftest import CORPUS_DIR, InProcessGateway, format_matrix, load_corpus, post_chat, run_selftest
from tests.conftest import CONFIG, DEMO_KEYS


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    path = tmp_path_factory.mktemp("audit") / "audit.jsonl"
    server = InProcessGateway(str(CONFIG / "balanced.yaml"), str(CONFIG / "identities.yaml"), str(path))
    yield server
    server.close()


def test_http_roundtrip(live) -> None:
    reply = post_chat(live.url, DEMO_KEYS["analyst"], {"model": "mock-gpt", "messages": [{"role": "user", "content": "What is UDP?"}]})
    assert reply.status == 200 and reply.headers["X-Gateway-Decision"] == "allow"
    assert reply.body["model"] == "mock-gpt" and reply.body["usage"]["total_tokens"] > 0


def test_http_block_has_openai_style_error(live) -> None:
    reply = post_chat(live.url, DEMO_KEYS["viewer"], {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    assert reply.status == 403
    assert reply.body["error"]["code"] == "model_not_allowed" and reply.body["error"]["type"] == "gateway_policy"


def test_health_over_http(live) -> None:
    with urllib.request.urlopen(live.url + "/healthz") as resp:  # noqa: S310 - loopback
        assert json.loads(resp.read())["status"] == "ok"


def test_corpus_has_enough_cases() -> None:
    cases = load_corpus(CORPUS_DIR)
    assert len(cases) >= 50
    categories = {c.category for c in cases}
    assert {"benign", "injection", "indirect_injection", "secret_leak", "pii", "role_violation", "rate_limit", "output_leak"} <= categories


def test_full_selftest_passes(tmp_path) -> None:
    audit_path = tmp_path / "selftest.jsonl"
    results, used = run_selftest(str(CONFIG / "balanced.yaml"), str(CONFIG / "identities.yaml"), audit_path=str(audit_path))
    failed = [r for r in results if not r.passed]
    assert not failed, format_matrix(results)
    assert used == str(audit_path)
    chain = audit.verify(audit_path)
    assert chain.ok and chain.records >= len(results)
