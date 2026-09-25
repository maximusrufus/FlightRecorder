import pytest
from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod
from flightrecorder.auth import KeyStore


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
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

    keystore = KeyStore(str(tmp_path / "api_keys.json"))
    key_a = keystore.create_key("tenantA")
    key_b = keystore.create_key("tenantB")

    tc = TestClient(proxy_mod.app)
    return tc, key_a, key_b


def test_no_auth_header_rejected(app_client):
    client, _, _ = app_client
    r = client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "x",
        },
    )
    assert r.status_code == 401


def test_bogus_key_rejected(app_client):
    client, _, _ = app_client
    r = client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "x",
        },
        headers={"Authorization": "Bearer not-a-real-key"},
    )
    assert r.status_code == 401


def test_tenant_is_derived_from_key_not_body(app_client):
    client, key_a, _ = app_client
    r = client.post(
        "/v1/records",
        json={
            "tenant": "tenantA",  # matches key -> allowed
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "x",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert r.status_code == 201


def test_body_tenant_mismatch_rejected_403(app_client):
    client, key_a, _ = app_client
    r = client.post(
        "/v1/records",
        json={
            "tenant": "tenantB-victim",  # attacker holding key_a tries to claim tenantB
            "agent_id": "attacker",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "INJECTED",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert r.status_code == 403


def test_export_and_verify_scoped_to_callers_own_tenant(app_client):
    client, key_a, key_b = app_client
    client.post(
        "/v1/records",
        json={
            "agent_id": "a",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "secret A",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    client.post(
        "/v1/records",
        json={
            "agent_id": "b",
            "model": "m",
            "model_version": "v",
            "kind": "prompt",
            "payload": "secret B",
        },
        headers={"Authorization": f"Bearer {key_b}"},
    )

    v_a = client.get("/v1/verify", headers={"Authorization": f"Bearer {key_a}"})
    assert v_a.json()["n_records"] == 1

    v_b = client.get("/v1/verify", headers={"Authorization": f"Bearer {key_b}"})
    assert v_b.json()["n_records"] == 1

    import io
    import zipfile

    export_a = client.get("/v1/export", headers={"Authorization": f"Bearer {key_a}"})
    with zipfile.ZipFile(io.BytesIO(export_a.content)) as zf:
        records = zf.read("records.jsonl").decode()
    assert "secret A" not in records  # payload is encrypted, but tenant field must be present
    assert '"tenant":"tenantA"' in records.replace(" ", "") or '"tenant": "tenantA"' in records
    assert "tenantB" not in records


def test_no_auth_cannot_export_victim_tenant(app_client):
    client, _, _ = app_client
    r = client.get("/v1/export")
    assert r.status_code == 401
