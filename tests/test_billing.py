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
    package or network. Models the `StripeClient` shape (never the
    deprecated global `stripe.api_key = ...` pattern)."""
    fake = types.ModuleType("stripe")

    class _FakeCheckoutSession:
        url = "https://checkout.stripe.com/fake-session"

    class _FakePortalSession:
        url = "https://billing.stripe.com/fake-portal"

    class _CheckoutSessionsService:
        def __init__(self, calls):
            self.calls = calls

        def create(self, params=None, options=None):
            self.calls.append(dict(params or {}))
            return _FakeCheckoutSession()

    class _PortalSessionsService:
        def __init__(self, calls):
            self.calls = calls

        def create(self, params=None, options=None):
            self.calls.append(dict(params or {}))
            return _FakePortalSession()

    class _V1:
        def __init__(self, checkout_calls, portal_calls):
            self.checkout = types.SimpleNamespace(sessions=_CheckoutSessionsService(checkout_calls))
            self.billing_portal = types.SimpleNamespace(
                sessions=_PortalSessionsService(portal_calls)
            )

    class _FakeStripeClient:
        instances: list = []

        def __init__(self, api_key):
            self.api_key = api_key
            self.checkout_calls: list = []
            self.portal_calls: list = []
            self.v1 = _V1(self.checkout_calls, self.portal_calls)
            _FakeStripeClient.instances.append(self)

    fake.StripeClient = _FakeStripeClient

    class _FakeWebhook:
        @staticmethod
        def construct_event(payload, sig_header, secret):
            """Mirrors the real SDK: returns a genuine `stripe.Event` (a
            StripeObject, not a dict), built from `payload` via
            `stripe.Event.construct_from` -- so tests exercise the same
            downstream normalization production traffic requires."""
            import json

            import stripe as real_stripe

            return real_stripe.Event.construct_from(json.loads(payload), key=None)

    fake.Webhook = _FakeWebhook
    fake.Event = __import__("stripe").Event
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


def test_checkout_uses_stripe_client_no_payment_method_types_no_global_api_key(app, monkeypatch):
    fake = _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_fake")
    monkeypatch.setenv("STRIPE_PRICE_CORE", "price_core_fake")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro_fake")
    monkeypatch.setenv("STRIPE_PRICE_BUSINESS", "price_business_fake")
    assert not hasattr(fake, "api_key")

    client = TestClient(app)
    resp = client.post("/billing/checkout/core", params={"tenant": "acme"}, follow_redirects=False)
    assert resp.status_code == 303

    instance = fake.StripeClient.instances[-1]
    call = instance.checkout_calls[0]
    assert "payment_method_types" not in call
    assert call["client_reference_id"] == "acme"
    assert call["integration_identifier"].startswith("flightrecorder-core-")
    assert len(call["integration_identifier"].rsplit("-", 1)[-1]) == 8


def test_checkout_customer_email_passed_through(app, monkeypatch):
    fake = _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_fake")
    monkeypatch.setenv("STRIPE_PRICE_CORE", "price_core_fake")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro_fake")
    monkeypatch.setenv("STRIPE_PRICE_BUSINESS", "price_business_fake")

    client = TestClient(app)
    client.post(
        "/billing/checkout/core",
        params={"tenant": "acme", "customer_email": "a@example.com"},
        follow_redirects=False,
    )
    instance = fake.StripeClient.instances[-1]
    assert instance.checkout_calls[0]["customer_email"] == "a@example.com"


def test_webhook_async_payment_succeeded_unpaid_no_fulfillment(app, monkeypatch, tmp_path):
    import json

    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fake")
    monkeypatch.setenv("FLIGHTRECORDER_DATA_DIR", str(tmp_path))

    client = TestClient(app)
    payload = {
        "id": "evt_async",
        "type": "checkout.session.async_payment_succeeded",
        "data": {
            "object": {
                "client_reference_id": "acme-async",
                "payment_status": "unpaid",
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

    from flightrecorder.plans import PlanStore

    store = PlanStore(tmp_path / "plans.json")
    assert store.get_plan("acme-async") == "free"


def test_webhook_duplicate_event_id_no_double_fulfillment(app, monkeypatch, tmp_path):
    import json

    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fake")
    monkeypatch.setenv("FLIGHTRECORDER_DATA_DIR", str(tmp_path))

    client = TestClient(app)
    payload = {
        "id": "evt_dup",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": "acme-dup",
                "payment_status": "paid",
                "metadata": {"plan": "pro"},
            }
        },
    }
    body = json.dumps(payload).encode()
    resp1 = client.post("/stripe/webhook", content=body, headers={"stripe-signature": "fake-sig"})
    resp2 = client.post("/stripe/webhook", content=body, headers={"stripe-signature": "fake-sig"})
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp2.json().get("duplicate") is True


def test_webhook_subscription_deleted_downgrades(app, monkeypatch, tmp_path):
    import json

    from flightrecorder.plans import PlanStore

    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_fake")
    monkeypatch.setenv("FLIGHTRECORDER_DATA_DIR", str(tmp_path))

    store = PlanStore(tmp_path / "plans.json")
    store.set_plan("acme-sub", "pro")
    store.set_stripe_customer("acme-sub", "cus_sub")

    client = TestClient(app)
    payload = {
        "id": "evt_sub_deleted",
        "type": "customer.subscription.deleted",
        "data": {"object": {"id": "sub_1", "customer": "cus_sub", "status": "canceled"}},
    }
    resp = client.post(
        "/stripe/webhook",
        content=json.dumps(payload).encode(),
        headers={"stripe-signature": "fake-sig"},
    )
    assert resp.status_code == 200
    assert store.get_plan("acme-sub") == "free"


def test_billing_portal_404_for_unknown_tenant(app, monkeypatch):
    _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_fake")
    client = TestClient(app)
    resp = client.post("/billing/portal", params={"tenant": "no-such-tenant"})
    assert resp.status_code == 404


def test_billing_portal_redirects_for_known_customer(app, monkeypatch, tmp_path):
    fake = _install_fake_stripe_module(monkeypatch)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_fake")
    monkeypatch.setenv("FLIGHTRECORDER_DATA_DIR", str(tmp_path))

    from flightrecorder.plans import PlanStore

    store = PlanStore(tmp_path / "plans.json")
    store.set_stripe_customer("acme-portal", "cus_portal")

    client = TestClient(app)
    resp = client.post("/billing/portal", params={"tenant": "acme-portal"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "billing.stripe.com" in resp.headers["location"]
    assert fake.StripeClient.instances[-1].portal_calls[0]["customer"] == "cus_portal"
