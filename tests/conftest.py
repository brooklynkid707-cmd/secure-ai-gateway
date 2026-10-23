"""Shared fixtures: repo paths, an in-process mock upstream and a Flask test client."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gateway.mock_llm import MockServer  # noqa: E402
from gateway.selftest import DEMO_KEYS, PINNED_CLOCK  # noqa: E402
from gateway.server import GatewaySettings, create_app  # noqa: E402

CONFIG = ROOT / "config"


@pytest.fixture(scope="session")
def mock_upstream():
    """A mock OpenAI-compatible server on an ephemeral loopback port."""
    server = MockServer().start()
    yield server
    server.stop()


@pytest.fixture
def app(mock_upstream, tmp_path):
    """Gateway app wired to the mock upstream with a per-test audit file and pinned clock."""
    settings = GatewaySettings(
        policy_path=str(CONFIG / "balanced.yaml"),
        identities_path=str(CONFIG / "identities.yaml"),
        upstream_url=mock_upstream.url,
        audit_path=str(tmp_path / "audit.jsonl"),
        canary="CANARY-testtoken1234",
    )
    application = create_app(settings)
    application.extensions["gateway"].policy_engine.clock = PINNED_CLOCK
    return application


@pytest.fixture
def gw(app):
    """The Gateway object behind the app."""
    return app.extensions["gateway"]


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


def auth(identity: str) -> dict[str, str]:
    """Authorization header for a demo identity."""
    return {"Authorization": f"Bearer {DEMO_KEYS[identity]}"}


def chat(client, identity: str, content: str, **extra):
    """POST a single-user-message chat request."""
    body = {"model": "mock-gpt", "messages": [{"role": "user", "content": content}], **extra}
    return client.post("/v1/chat/completions", json=body, headers=auth(identity))
