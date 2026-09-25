"""Tests for the `flightrecorder.Recorder` SDK — local ledger mode and the
OpenAI-compatible client wrapper. NEVER calls a real OpenAI SDK/API — the
"client" here is a hand-written fake, as required."""

from __future__ import annotations

import json

from flightrecorder import Recorder
from flightrecorder import ledger as ledger_mod


class _FakeMessage:
    def __init__(self, content: str, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class _FakeChoice:
    def __init__(self, message: _FakeMessage):
        self.message = message


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [_FakeChoice(_FakeMessage(content))]


class _FakeCompletions:
    def create(self, *, model: str, messages: list[dict]):
        return _FakeResponse(f"echo: {messages[-1]['content']}")


class _FakeChat:
    def __init__(self):
        self.completions = _FakeCompletions()


class _FakeOpenAIClient:
    def __init__(self):
        self.chat = _FakeChat()


def test_local_recorder_writes_hash_chained_ledger(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    rec = Recorder(local_path=ledger_path, tenant="acme", agent_id="agent-1")

    r1 = rec.record(kind="prompt", payload="hello world")
    r2 = rec.record(kind="output", payload="hi there")

    assert r1["seq"] == 1
    assert r2["seq"] == 2

    records = list(ledger_mod.Ledger(ledger_path).read_all())
    result = ledger_mod.verify_records(records)
    assert result.ok
    assert result.n_records == 2


def test_tool_decorator_records_call_and_result(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    rec = Recorder(local_path=ledger_path, tenant="acme", agent_id="agent-1")

    @rec.tool
    def add(a: int, b: int) -> int:
        return a + b

    result = add(2, 3)
    assert result == 5

    records = list(ledger_mod.Ledger(ledger_path).read_all())
    kinds = [r["kind"] for r in records]
    assert kinds == ["tool_call", "tool_result"]


def test_tool_decorator_records_error_outcome(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    rec = Recorder(local_path=ledger_path, tenant="acme", agent_id="agent-1")

    @rec.tool
    def boom():
        raise ValueError("kaboom")

    try:
        boom()
    except ValueError:
        pass

    records = list(ledger_mod.Ledger(ledger_path).read_all())
    result_record = [r for r in records if r["kind"] == "tool_result"][0]
    payload = rec._ledger.decrypt_record_payload(result_record)
    body = json.loads(payload.decode("utf-8"))
    assert body["outcome"] == "error"
    assert "kaboom" in body["error"]


def test_wrap_openai_records_output_with_hashes_and_cost(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    rec = Recorder(local_path=ledger_path, tenant="acme", agent_id="agent-1")
    fake_client = _FakeOpenAIClient()

    wrapped = rec.wrap_openai(fake_client)
    response = wrapped.chat.completions.create(
        model="fake-model-v1", messages=[{"role": "user", "content": "ping"}]
    )
    assert response.choices[0].message.content == "echo: ping"

    records = list(ledger_mod.Ledger(ledger_path).read_all())
    output_records = [r for r in records if r["kind"] == "output"]
    assert len(output_records) == 1
    payload = rec._ledger.decrypt_record_payload(output_records[0])
    body = json.loads(payload.decode("utf-8"))
    assert body["model"] == "fake-model-v1"
    assert len(body["prompt_hash"]) == 64
    assert len(body["output_hash"]) == 64
    assert body["estimated_cost_usd"] >= 0
    assert body["trust_level"] == "unverified"


def test_recorder_requires_api_key_for_hosted_url():
    import pytest

    from flightrecorder.recorder import RecorderError

    with pytest.raises(RecorderError):
        Recorder(url="https://example.com")
