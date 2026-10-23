"""Hash-chained audit log: integrity, resume and tamper detection."""

from __future__ import annotations

import json

from gateway import audit


def _write(path, n: int = 5) -> audit.AuditLog:
    log = audit.AuditLog(path)
    for i in range(n):
        log.append("chat_completion", request_id=f"r{i}", decision="allow" if i % 2 else "block")
    return log


def test_chain_verifies(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path)
    res = audit.verify(path)
    assert res.ok and res.records == 5


def test_first_record_links_to_genesis(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path, 1)
    rec = json.loads(path.read_text().splitlines()[0])
    assert rec["prev_hash"] == audit.GENESIS and rec["seq"] == 1
    assert audit.compute_hash(audit.GENESIS, rec) == rec["hash"]


def test_resume_keeps_single_chain(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path, 3)
    log2 = audit.AuditLog(path)  # simulate restart
    log2.append("policy_reloaded")
    res = audit.verify(path)
    assert res.ok and res.records == 4


def test_modified_record_detected(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["decision"] = "allow"  # flip a block to an allow
    lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    res = audit.verify(path)
    assert not res.ok and res.first_bad_seq == 3 and "modified" in res.reason


def test_deleted_record_detected(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    res = audit.verify(path)
    assert not res.ok and res.first_bad_seq == 2


def test_reordered_records_detected(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path)
    lines = path.read_text().splitlines()
    lines[3], lines[4] = lines[4], lines[3]
    path.write_text("\n".join(lines) + "\n")
    assert not audit.verify(path).ok


def test_appended_forged_record_detected(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path)
    with path.open("a") as fh:
        fh.write(json.dumps({"seq": 6, "event": "x", "prev_hash": "ff" * 32, "hash": "00" * 32}) + "\n")
    res = audit.verify(path)
    assert not res.ok and res.first_bad_seq == 6


def test_malformed_line_detected(tmp_path) -> None:
    path = tmp_path / "a.jsonl"
    _write(path, 2)
    with path.open("a") as fh:
        fh.write("{not json\n")
    res = audit.verify(path)
    assert not res.ok and "malformed" in res.reason


def test_missing_file_is_empty_chain(tmp_path) -> None:
    res = audit.verify(tmp_path / "nope.jsonl")
    assert res.ok and res.records == 0
