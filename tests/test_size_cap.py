import pytest

from flightrecorder.ledger import Ledger, LedgerError


def test_ledger_append_rejects_oversized_payload(tmp_ledger_path, monkeypatch):
    monkeypatch.setenv("FLIGHTRECORDER_MAX_PAYLOAD_BYTES", "100")
    led = Ledger(tmp_ledger_path)
    with pytest.raises(LedgerError):
        led.append(
            tenant="acme",
            agent_id="a",
            model="m",
            model_version="v1",
            kind="prompt",
            payload=b"x" * 101,
        )


def test_ledger_append_accepts_payload_at_cap(tmp_ledger_path, monkeypatch):
    monkeypatch.setenv("FLIGHTRECORDER_MAX_PAYLOAD_BYTES", "100")
    led = Ledger(tmp_ledger_path)
    led.append(
        tenant="acme",
        agent_id="a",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"x" * 100,
    )
    assert len(list(led.read_all())) == 1


def test_api_returns_413_for_oversized_payload(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import flightrecorder.proxy as proxy_mod
    from flightrecorder.auth import KeyStore

    monkeypatch.setenv("FLIGHTRECORDER_MAX_PAYLOAD_BYTES", "50")
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
    client = TestClient(proxy_mod.app)

    r = client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "x" * 100,
        },
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert r.status_code == 413
