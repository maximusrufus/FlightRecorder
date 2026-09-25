"""Item 6: signed checkpoints detect tail truncation that a pure hash chain
misses entirely (Attack 1 from the adversarial review)."""

import json
import zipfile

import pytest
from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod
from flightrecorder.auth import KeyStore
from flightrecorder.verify_cli import main as verify_cli_main
from flightrecorder.verify_cli import verify_export


@pytest.fixture()
def client(tmp_path, monkeypatch, real_keys_env):
    monkeypatch.setattr(proxy_mod, "LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(proxy_mod, "KEYS_PATH", str(tmp_path / "api_keys.json"))
    monkeypatch.setattr(proxy_mod, "PLANS_PATH", str(tmp_path / "plans.json"))
    monkeypatch.setattr(proxy_mod, "WITNESS_DIR", str(tmp_path / "witness"))
    monkeypatch.setenv("FLIGHTRECORDER_CHECKPOINT_EVERY_N", "2")
    proxy_mod._ledger = None
    proxy_mod._keystore = None
    proxy_mod._witness = None
    proxy_mod._plans = None
    proxy_mod._scheduler = proxy_mod.checkpoint_mod.CheckpointScheduler(
        every_n=2, every_seconds=99999
    )

    keystore = KeyStore(str(tmp_path / "api_keys.json"))
    raw_key = keystore.create_key("acme")
    tc = TestClient(proxy_mod.app)
    tc.headers.update({"Authorization": f"Bearer {raw_key}"})
    return tc


def test_checkpoints_emitted_and_present_in_export(client):
    for i in range(5):
        client.post(
            "/v1/records",
            json={
                "agent_id": "a",
                "model": "m",
                "model_version": "v",
                "kind": "prompt",
                "payload": f"p{i}",
            },
        )
    resp = client.get("/v1/export")
    with zipfile.ZipFile(__import__("io").BytesIO(resp.content)) as zf:
        cps = [
            json.loads(ln)
            for ln in zf.read("checkpoints.jsonl").decode().splitlines()
            if ln
        ]
    assert len(cps) >= 1


def test_tail_truncation_detected_via_checkpoint(client, tmp_path):
    for i in range(6):
        client.post(
            "/v1/records",
            json={
                "agent_id": "a",
                "model": "m",
                "model_version": "v",
                "kind": "prompt",
                "payload": f"p{i}",
            },
        )
    resp = client.get("/v1/export")
    with zipfile.ZipFile(__import__("io").BytesIO(resp.content)) as zf:
        records_raw = zf.read("records.jsonl").decode()
        pub_hex = zf.read("public_key.hex").decode()
        other = {n: zf.read(n) for n in zf.namelist() if n != "records.jsonl"}

    # Attacker truncates the tail (deletes the last 2 records) -- a
    # signature-only/hash-only verify would see a perfectly self-consistent
    # shorter chain and report INTACT.
    lines = [ln for ln in records_raw.splitlines() if ln.strip()]
    truncated_lines = lines[:-2]
    truncated = "\n".join(truncated_lines) + "\n"

    tampered_zip = tmp_path / "truncated.zip"
    with zipfile.ZipFile(tampered_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("records.jsonl", truncated)
        for name, data in other.items():
            zf.writestr(name, data)

    ok, msg = verify_export(str(tampered_zip), trusted_key=pub_hex)
    assert ok is False, (
        "truncation must be detected via a checkpoint whose seq exceeds the truncated max seq"
    )

    exit_code = verify_cli_main([str(tampered_zip), "--trusted-key", pub_hex])
    assert exit_code == 2


def test_expected_head_mismatch_detected(client, tmp_path):
    client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "p0",
        },
    )
    resp = client.get("/v1/export")
    zip_path = tmp_path / "export.zip"
    zip_path.write_bytes(resp.content)
    with zipfile.ZipFile(zip_path) as zf:
        pub_hex = zf.read("public_key.hex").decode()

    exit_code = verify_cli_main(
        [str(zip_path), "--trusted-key", pub_hex, "--expected-head", "1:" + "f" * 64]
    )
    assert exit_code == 2
