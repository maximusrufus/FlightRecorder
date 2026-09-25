"""Tests for the extended /v1/export (MAPPING.md, CSV format) and the
plan-limit 429 enforcement on /v1/records."""

from __future__ import annotations

import zipfile

import pytest
from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod
from flightrecorder.auth import KeyStore
from flightrecorder.plans import PlanStore


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
    tc.tmp_path = tmp_path
    return tc


def _ingest(client, n=1):
    for i in range(n):
        r = client.post(
            "/v1/records",
            json={
                "agent_id": "agent-1",
                "model": "m",
                "model_version": "v1",
                "kind": "output",
                "payload": f"output {i}",
            },
        )
        assert r.status_code == 201, r.text


def test_export_bundle_contains_mapping_md_with_real_content(client):
    _ingest(client, 2)
    resp = client.get("/v1/export")
    assert resp.status_code == 200
    zip_path = client.tmp_path / "export.zip"
    zip_path.write_bytes(resp.content)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert "MAPPING.md" in names
        mapping_text = zf.read("MAPPING.md").decode("utf-8")

    assert "EU AI Act" in mapping_text
    assert "ISO/IEC 42001" in mapping_text
    assert "17a-4(f)" in mapping_text
    assert "SOC 2 CC7" in mapping_text
    assert len(mapping_text) > 500


def test_export_format_csv_produces_records_csv(client):
    _ingest(client, 2)
    resp = client.get("/v1/export", params={"format": "csv"})
    assert resp.status_code == 200
    zip_path = client.tmp_path / "export_csv.zip"
    zip_path.write_bytes(resp.content)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert "records.csv" in names
        assert "records.jsonl" not in names
        csv_text = zf.read("records.csv").decode("utf-8")

    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("seq,ts,tenant")
    assert len(lines) == 3  # header + 2 records


def test_records_endpoint_returns_chain_hash(client):
    resp = client.post(
        "/v1/records",
        json={
            "agent_id": "agent-1",
            "model": "m",
            "model_version": "v1",
            "kind": "prompt",
            "payload": "hello",
        },
    )
    assert resp.status_code == 201 or resp.status_code == 200
    body = resp.json()
    assert "hash" in body
    assert len(body["hash"]) == 64


def test_plan_limit_returns_429_with_upgrade_hint(client, tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_mod, "PLANS_PATH", str(tmp_path / "plans2.json"))
    proxy_mod._plans = None
    store = PlanStore(str(tmp_path / "plans2.json"))
    store.set_plan("acme", "free")
    # Pre-fill usage to just below the limit so the next call tips over.
    from flightrecorder.plans import PLAN_LIMITS

    store.check_and_increment("acme", PLAN_LIMITS["free"])

    resp = client.post(
        "/v1/records",
        json={
            "agent_id": "agent-1",
            "model": "m",
            "model_version": "v1",
            "kind": "prompt",
            "payload": "over limit",
        },
    )
    assert resp.status_code == 429
    assert "upgrade" in resp.json()["detail"]
