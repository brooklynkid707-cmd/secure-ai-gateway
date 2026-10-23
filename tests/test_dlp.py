"""Every DLP detector, the Luhn validator and reversible redaction."""

from __future__ import annotations

import pytest

from gateway import dlp

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Amazon's documentation example key
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.mark.parametrize(
    "number, valid",
    [("4111111111111111", True), ("4111 1111 1111 1111", True), ("5500-0000-0000-0004", True),
     ("378282246310005", True), ("4111111111111112", False), ("1234567812345678", False), ("4111", False)],
)
def test_luhn(number, valid) -> None:
    assert dlp.luhn_valid(number) is valid


@pytest.mark.parametrize(
    "text, detector",
    [
        (f"key {AWS_KEY} here", "aws_access_key"),
        ("ASIAIOSFODNN7EXAMPLE temp creds", "aws_access_key"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key"),
        ("ghp_" + "a" * 36, "github_token"),
        ("github_pat_" + "A" * 30, "github_token"),
        ("XOXB-000000000000-000000000000-ExampleExampleEx", "slack_token"),
        ("sk-abcdefghijklmnopqrstuvwxyz0123", "openai_style_key"),
        (JWT, "jwt"),
        ("API_KEY=abcdefghijklmnop12345", "generic_api_key"),
        ("client_secret: 'zzzzzzzzzzzzzzzzzzzz'", "generic_api_key"),
        ("DB_PASSWORD=Hunter2!!Rotate", "password_assignment"),
        ("card 4111 1111 1111 1111", "credit_card"),
        ("ssn 219-09-9999", "ssn"),
        ("mail me at a.b+c@example.com", "email"),
        ("call (555) 867-5309", "phone"),
        ("call +1 555-867-5309", "phone"),
        ("host 10.0.4.17 down", "ipv4_private"),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "private_key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key"),
    ],
)
def test_detectors_hit(text, detector) -> None:
    assert detector in {f.detector for f in dlp.scan(text)}


@pytest.mark.parametrize(
    "text",
    [
        "The AKIA prefix identifies access keys",
        "Order 4111 1111 1111 1112 is stuck",  # Luhn fails
        "000-12-3456 is not a valid SSN",  # invalid area
        "666-12-3456",
        "9xx: 912-34-5678",
        "ratio 3.5 and 2026-10-22",
        "public IP 203.0.113.9",  # documentation range, not RFC1918
        "password policy: 12 chars",  # no value assignment of 6+ non-space chars after colon? '12' is too short
        "eyJonly.two",
    ],
)
def test_detectors_do_not_fire(text) -> None:
    assert dlp.scan(text) == []


def test_apply_redacts_and_restores() -> None:
    text = "Email dana@example.com or call 555-201-0199 about card 4111 1111 1111 1111."
    rmap = dlp.RedactionMap()
    res = dlp.apply(text, {}, "redact", rmap)
    assert res.text == "Email [[EMAIL_1]] or call [[PHONE_1]] about card [[CREDIT_CARD_1]]."
    assert "dana@example.com" not in res.text
    assert sorted(res.redacted) == ["credit_card", "email", "phone"]
    reply = "I will contact [[EMAIL_1]] and mention [[CREDIT_CARD_1]]."
    assert rmap.restore(reply) == "I will contact dana@example.com and mention 4111 1111 1111 1111."


def test_same_value_same_placeholder() -> None:
    rmap = dlp.RedactionMap()
    res = dlp.apply("a@example.com then a@example.com then b@example.com", {}, "redact", rmap)
    assert res.text == "[[EMAIL_1]] then [[EMAIL_1]] then [[EMAIL_2]]"
    assert len(rmap) == 2


def test_block_action_wins_and_leaves_text_untouched() -> None:
    text = f"key {AWS_KEY} mail a@example.com"
    res = dlp.apply(text, {"aws_access_key": "block"}, "redact")
    assert res.blocked_by == ["aws_access_key"]
    assert res.text == text


def test_warn_action_keeps_text() -> None:
    res = dlp.apply("host 10.0.0.5", {"ipv4_private": "warn"}, "redact")
    assert res.warned == ["ipv4_private"] and res.text == "host 10.0.0.5"


def test_enabled_subset() -> None:
    found = dlp.scan("a@example.com 555-867-5309", enabled=["email"])
    assert [f.detector for f in found] == ["email"]


def test_preview_masks_value() -> None:
    f = dlp.scan(f"{AWS_KEY}")[0]
    assert AWS_KEY not in f.preview and f.preview.startswith("AK") and f.preview.endswith("LE")
