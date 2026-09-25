import zipfile

import pytest
from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod
from flightrecorder.auth import KeyStore
from flightrecorder.verify_cli import main as verify_cli_main


@pytest.fixture()
def dev_client(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTRECORDER_DEV", "1")
    monkeypatch.setattr(proxy_mod, "LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(proxy_mod, "KEYS_PATH", str(tmp_path / "api_keys.json"))
    monkeypatch.setattr(proxy_mod, "PLANS_PATH", str(tmp_path / "plans.json"))
    monkeypatch.setattr(proxy_mod, "WITNESS_DIR", str(tmp_path / "witness"))
    proxy_mod._ledger = None
    proxy_mod._keystore = None
    proxy_mod._witness = None
    proxy_mod._plans = None

    keystore = KeyStore(str(tmp_path / "api_keys.json"))
    raw_key = keystore.create_key("acme")
    tc = TestClient(proxy_mod.app)
    tc.headers.update({"Authorization": f"Bearer {raw_key}"})
    return tc


def test_records_stamped_dev_mode_true(dev_client):
    r = dev_client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "hi",
        },
    )
    assert r.json()["dev_mode"] is True


def test_verify_cli_exits_3_on_dev_export(dev_client, tmp_path):
    dev_client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "hi",
        },
    )
    resp = dev_client.get("/v1/export")
    zip_path = tmp_path / "dev_export.zip"
    zip_path.write_bytes(resp.content)

    with zipfile.ZipFile(zip_path) as zf:
        pub_hex = zf.read("public_key.hex").decode()

    exit_code = verify_cli_main([str(zip_path), "--trusted-key", pub_hex])
    assert exit_code == 3
