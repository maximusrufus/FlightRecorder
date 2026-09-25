"""Tests for flightrecorder.policy — ported from ActionFirewall, plus the
new evaluate_and_record() ledger-recording gate."""

from __future__ import annotations

import json

from flightrecorder import ledger as ledger_mod
from flightrecorder.policy import ALLOW, BLOCK, HOLD, Policy


def test_allow_by_default():
    p = Policy()
    d = p.evaluate({"action": "noop"})
    assert d.verdict == ALLOW
    assert d.allowed


def test_block_if_fires():
    p = Policy().block_if(lambda a: a.get("action") == "delete_account", "destructive")
    d = p.evaluate({"action": "delete_account"})
    assert d.verdict == BLOCK
    assert not d.allowed


def test_max_amount_holds_over_limit():
    p = Policy().max_amount("amount", 500)
    d = p.evaluate({"amount": 501})
    assert d.verdict == HOLD
    d2 = p.evaluate({"amount": 500})
    assert d2.verdict == ALLOW


def test_allow_only_blocks_unlisted_action():
    p = Policy().allow_only({"refund", "lookup"})
    d = p.evaluate({"action": "wire_transfer"})
    assert d.verdict == BLOCK


def test_require_field_blocks_missing():
    p = Policy().require_field("customer")
    d = p.evaluate({})
    assert d.verdict == BLOCK


def test_throwing_rule_fails_closed():
    def bad_predicate(a):
        raise RuntimeError("boom")

    p = Policy().block_if(bad_predicate, "should never matter")
    d = p.evaluate({})
    assert d.verdict == BLOCK
    assert "rule error" in d.reason


def test_evaluate_and_record_writes_verdict_to_ledger(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    led = ledger_mod.Ledger(ledger_path)
    p = Policy().max_amount("amount", 100)

    decision = p.evaluate_and_record(
        {"action": "refund", "amount": 999},
        led,
        tenant="acme",
        agent_id="agent-1",
    )
    assert decision.verdict == HOLD

    records = list(led.read_all())
    assert len(records) == 1
    assert records[0]["kind"] == "tool_result"
    payload = led.decrypt_record_payload(records[0])
    body = json.loads(payload.decode("utf-8"))
    assert body["verdict"] == "hold"
    assert body["action"]["amount"] == 999
