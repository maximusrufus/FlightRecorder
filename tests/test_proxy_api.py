import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod
from flightrecorder.auth import KeyStore


@pytest.fixture()
def client(tmp_path, monkeypatch, real_keys_env):
    monkeypatch.setattr(proxy_mod, "LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(proxy_mod, "ANCHOR_PATH", str(tmp_path / "anchors.jsonl"))
    monkeypatch.setattr(proxy_mod, "KEYS_PATH", str(tmp_path / "api_keys.json"))
    monkeypatch.setattr(proxy_mod, "PLANS_PATH", str(tmp_path / "plans.json"))
    monkeypatch.setattr(proxy_mod, "WITNESS_DIR", str(tmp_path / "witness"))
    proxy_mod._ledger = None
    proxy_mod._anchors = None
    proxy_mod._keystore = None
    proxy_mod._witness = None
    proxy_mod._plans = None
    proxy_mod._scheduler = proxy_mod.checkpoint_mod.CheckpointScheduler()

    keystore = KeyStore(str(tmp_path / "api_keys.json"))
    raw_key = keystore.create_key("acme")

    tc = TestClient(proxy_mod.app)
    tc.headers.update({"Authorization": f"Bearer {raw_key}"})
    tc.raw_key = raw_key
    return tc


def test_ingest_record_then_verify(client):
    resp = client.post(
        "/v1/records",
        json={
            "agent_id": "agent-1",
            "model": "in-house-llm",
            "model_version": "v1",
            "kind": "prompt",
            "payload": "what is the position size for AAPL?",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["seq"] == 1

    v = client.get("/v1/verify")
    assert v.status_code == 200
    assert v.json()["intact"] is True
    assert v.json()["n_records"] == 1


def test_otel_ingest_maps_genai_semconv_attributes(client):
    resp = client.post(
        "/v1/otel",
        json={
            "agent_id": "agent-1",
            "attributes": {
                "gen_ai.request.model": "gpt-in-house",
                "gen_ai.response.model": "gpt-in-house-v2",
                "gen_ai.prompt": "summarize this filing",
                "gen_ai.completion": "the filing says X",
                "gen_ai.tool.name": "edgar_lookup",
                "gen_ai.tool.call.id": "call-1",
                "gen_ai.tool.arguments": {"cik": "0000320193"},
                "gen_ai.tool.result": {"company": "Apple Inc"},
            },
        },
    )
    assert resp.status_code == 200
    out = resp.json()
    assert len(out) == 4

    v = client.get("/v1/verify")
    assert v.json()["intact"] is True
    assert v.json()["n_records"] == 4


def test_otel_ingest_rejects_unrecognized_span(client):
    resp = client.post(
        "/v1/otel",
        json={"agent_id": "a", "attributes": {"unrelated.attr": "x"}},
    )
    assert resp.status_code == 400


def test_export_then_verify_cli_roundtrip(client, tmp_path):
    for i in range(3):
        client.post(
            "/v1/records",
            json={
                "agent_id": "agent-1",
                "model": "m",
                "model_version": "v1",
                "kind": "output",
                "payload": f"output {i}",
            },
        )

    resp = client.get("/v1/export")
    assert resp.status_code == 200
    zip_path = tmp_path / "export.zip"
    zip_path.write_bytes(resp.content)

    from flightrecorder.verify_cli import verify_export

    with zipfile.ZipFile(zip_path) as zf:
        pub_hex = zf.read("public_key.hex").decode()

    ok, message = verify_export(str(zip_path), trusted_key=pub_hex)
    assert ok is True
    assert "INTACT" in message

    with zipfile.ZipFile(zip_path, "r") as zf:
        records_raw = zf.read("records.jsonl").decode("utf-8")
        other = {n: zf.read(n) for n in zf.namelist() if n != "records.jsonl"}

    lines = records_raw.splitlines()
    rec = json.loads(lines[1])
    rec["payload_hash"] = "f" * 64
    lines[1] = json.dumps(rec)
    tampered_records = "\n".join(lines) + "\n"

    tampered_zip = tmp_path / "export_tampered.zip"
    with zipfile.ZipFile(tampered_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("records.jsonl", tampered_records)
        for name, data in other.items():
            zf.writestr(name, data)

    from flightrecorder.verify_cli import main as verify_cli_main

    exit_code = verify_cli_main([str(tampered_zip), "--trusted-key", pub_hex])
    assert exit_code == 2
