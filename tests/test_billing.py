"""Tests for flightrecorder.billing — Stripe is fully mocked; the real
`stripe` package/API is never called. Covers: unconfigured (no keys) ->
503; PAYMENT_LINK_URL fallback -> redirect; Stripe configured (mocked) ->
checkout session URL; webhook signature verification (mocked) updates plan.
"""

from __future__ import annotations

import sys
import types

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from flightrecorder import billing


@pytest.fixture()
def app(monkeypatch):
    application = FastAPI()
    application.include_router(billing.router)
    return application


def test_checkout_unconfigured_returns_503(app, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("PAYMENT_LINK_URL", raising=False)
    client = TestClient(app)
    resp = client.post("/billing/checkout/core", follow_redirects=False)
    assert resp.status_code == 503
    assert resp.json()["error"] == "payments not configured"


def test_checkout_payment_link_fallback_redirects(app, monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.setenv("PAYMENT_LINK_URL", "https://buy.example.com/core")
    client = TestClient(app)
    resp = client.post("/billing/checkout/core", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "https://buy.example.com/core"


def test_checkout_unknown_plan_400(app, monkeypatch):
    monkeypatch.setenv("PAYMENT_LINK_URL", "https://buy.example.com/x")
    client = TestClient(app)
    resp = client.post("/billing/checkout/platinum", follow_redirects=False)
    assert resp.status_code == 400


def _install_fake_stripe_module(monkeypatch):
    """Installs a minimal fake `stripe` module into sys.modules so
    billing.py's lazy `import stripe` picks it up — never touches the real
    package or network."""
    fake = types.ModuleType("stripe")

    class _FakeSession:
        url = "https://checkout.stripe.com/fake-session"

    class _FakeCheckout:
        class Session:
            @staticmethod
            def create(**kwargs):
                return _FakeSession()

    fake.checkout = _FakeCheckout()
    fake.api_key = None

    class _FakeWebhook:
        @staticmethod
        def construct_event(payload, sig_header, secret):
            import json

            return json.loads(payload)

    fake.Webhook = _FakeWebhook
    monkeypatch.setitem(sys.modules, "stripe", fake)
    return fake


def test_checkout_stripe_configured_returns_stripe_session_url(app, monkeypatch):
    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setenv("STRIPE_PRICE_CORE", "price_core_fake")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro_fake")
    monkeypatch.setenv("STRIPE_PRICE_BUSINESS", "price_business_fake")

    client = TestClient(app)
    resp = client.post("/billing/checkout/core", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "https://checkout.stripe.com/fake-session"


def test_webhook_missing_secret_returns_503(app, monkeypatch):
    _install_fake_stripe_module(monkeypatch)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    client = TestClient(app)
    resp = client.post("/stripe/webhook", content=b"{}")
    assert resp.status_code == 503


def test_webhook_updates_plan_on_checkout_completed(app, monkeypatch, tmp_path):
    import json

    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fake")
    monkeypatch.setenv("FLIGHTRECORDER_DATA_DIR", str(tmp_path))

    client = TestClient(app)
    payload = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": "acme",
                "metadata": {"plan": "pro"},
            }
        },
    }
    resp = client.post(
        "/stripe/webhook",
        content=json.dumps(payload).encode(),
        headers={"stripe-signature": "fake-sig"},
    )
    assert resp.status_code == 200
    assert resp.json()["received"] is True

    from flightrecorder.plans import PlanStore

    store = PlanStore(tmp_path / "plans.json")
    assert store.get_plan("acme") == "pro"
