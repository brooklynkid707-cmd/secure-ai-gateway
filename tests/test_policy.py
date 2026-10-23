"""Policy engine decisions for both shipped policies."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gateway.policy import PolicyEngine, load_policy
from tests.conftest import CONFIG

FRIDAY_NOON = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
SUNDAY_NOON = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
FRIDAY_NIGHT = datetime(2026, 10, 23, 23, 30, tzinfo=timezone.utc)

CODE = "import os\nfrom pathlib import Path\n\ndef scan(root):\n    return list(Path(root).rglob('*'))\n"


@pytest.fixture
def balanced() -> PolicyEngine:
    eng = PolicyEngine(load_policy(CONFIG / "balanced.yaml"))
    eng.clock = FRIDAY_NOON
    return eng


@pytest.fixture
def strict() -> PolicyEngine:
    eng = PolicyEngine(load_policy(CONFIG / "strict.yaml"))
    eng.clock = FRIDAY_NOON
    return eng


def _eval(eng, role, model="mock-gpt", tokens=None, tools=(), ip="127.0.0.1", text="hello", n=1):
    return eng.evaluate(role, model, tokens, list(tools), ip, text, n)


def test_balanced_allows_viewer_basic(balanced) -> None:
    d = _eval(balanced, "viewer")
    assert d.allowed and d.max_tokens == 512 and d.allowed_tools == [] and not d.client_system_prompt_allowed


def test_max_tokens_capped(balanced) -> None:
    d = _eval(balanced, "viewer", tokens=4000)
    assert d.allowed and d.max_tokens == 512 and d.warnings
    assert _eval(balanced, "viewer", tokens=100).max_tokens == 100


def test_model_allowlist(balanced) -> None:
    assert _eval(balanced, "viewer", model="gpt-4o").code == "model_not_allowed"
    assert _eval(balanced, "analyst", model="gpt-4o").allowed
    assert _eval(balanced, "admin", model="anything-else").allowed  # wildcard


def test_tools(balanced) -> None:
    assert _eval(balanced, "viewer", tools=["get_weather"]).code == "tool_not_allowed"
    assert _eval(balanced, "analyst", tools=["get_weather", "search_kb"]).allowed
    assert _eval(balanced, "analyst", tools=["run_query"]).code == "tool_not_allowed"
    assert _eval(balanced, "admin", tools=["run_query"]).allowed


def test_topics_by_role(balanced) -> None:
    d = _eval(balanced, "viewer", text=CODE)
    assert d.code == "topic_denied" and d.topics_hit == ["source_code"]
    assert _eval(balanced, "analyst", text=CODE).allowed
    assert _eval(balanced, "viewer", text="Customer ID: 4482\nDOB: 1980-01-01").topics_hit == ["customer_records"]
    assert _eval(balanced, "analyst", text="send me the passwords list").code == "topic_denied"
    assert _eval(balanced, "admin", text="send me the passwords list").allowed


def test_source_code_needs_two_patterns(balanced) -> None:
    assert _eval(balanced, "viewer", text="import this").allowed  # one pattern only


def test_hours_and_days(balanced, strict) -> None:
    balanced.clock = FRIDAY_NIGHT
    assert _eval(balanced, "viewer").code == "outside_hours"
    assert _eval(balanced, "analyst").allowed  # no hours rule for analysts
    strict.clock = SUNDAY_NOON
    assert _eval(strict, "analyst", ip="10.1.2.3").code == "outside_hours"
    strict.clock = FRIDAY_NOON
    assert _eval(strict, "analyst", ip="10.1.2.3").allowed


def test_window_crossing_midnight(tmp_path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("roles:\n  analyst:\n    hours: '22:00-06:00'\n")
    eng = PolicyEngine(load_policy(p))
    eng.clock = datetime(2026, 10, 23, 23, 0, tzinfo=timezone.utc)
    assert eng.evaluate("analyst", "m", None, [], "1.1.1.1", "x", 1).allowed
    eng.clock = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    assert eng.evaluate("analyst", "m", None, [], "1.1.1.1", "x", 1).code == "outside_hours"


def test_strict_role_and_network(strict) -> None:
    assert _eval(strict, "viewer").code == "role_denied"
    assert _eval(strict, "analyst", ip="203.0.113.5").code == "network_denied"
    assert _eval(strict, "analyst", ip="192.168.1.5").allowed
    assert _eval(strict, "admin", ip="192.168.1.5").code == "network_denied"


def test_unknown_role_denied(balanced) -> None:
    assert _eval(balanced, "contractor").code == "role_denied"


def test_size_limits(balanced) -> None:
    assert _eval(balanced, "viewer", n=21).code == "too_many_messages"
    assert _eval(balanced, "viewer", text="x" * 8001).code == "input_too_large"


def test_unknown_topic_reference_rejected(tmp_path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("roles:\n  viewer:\n    deny_topics: [nope]\n")
    with pytest.raises(ValueError):
        load_policy(p)


def test_policy_metadata(balanced, strict) -> None:
    assert balanced.policy.name == "balanced" and balanced.policy.injection_block == 0.7
    assert strict.policy.dlp_default_action == "block" and strict.policy.output_secret_action == "block"
