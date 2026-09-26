from fastapi.testclient import TestClient

import flightrecorder.app as app_mod


def test_preview_banner_shown_by_default(monkeypatch):
    monkeypatch.delenv("PREVIEW_MODE", raising=False)
    client = TestClient(app_mod.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'data-testid="preview-banner"' in resp.text
    assert "Preview deployment" in resp.text


def test_preview_banner_shown_when_explicitly_1(monkeypatch):
    monkeypatch.setenv("PREVIEW_MODE", "1")
    client = TestClient(app_mod.app)
    resp = client.get("/")
    assert 'data-testid="preview-banner"' in resp.text


def test_preview_banner_hidden_when_disabled(monkeypatch):
    monkeypatch.setenv("PREVIEW_MODE", "0")
    client = TestClient(app_mod.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'data-testid="preview-banner"' not in resp.text


def test_landing_page_has_working_contact_route():
    client = TestClient(app_mod.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "mailto:support@ripplarity.com" in resp.text
