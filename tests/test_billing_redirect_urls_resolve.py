"""Pins every Stripe `success_url`/`cancel_url` this app ever hands to
Checkout Sessions to a route that is actually registered on the FastAPI app.

A customer who pays and is redirected to a URL the app never registered
lands on a 404 -- their money is taken, fulfillment happens in the webhook,
and they see "Not Found". This test fails BEFORE that can happen again.
"""

from __future__ import annotations

import sys
import types

from flightrecorder import billing
from flightrecorder.app import app


def _registered_paths():
    """Recursively walks `app.routes`. Newer FastAPI wraps `include_router`
    results in `_IncludedRouter` objects with no `.path` of their own --
    the real sub-routes live on `.original_router.routes`."""
    paths: set[str] = set()

    def _walk(routes):
        for r in routes:
            path = getattr(r, "path", None)
            if path:
                paths.add(path)
            original_router = getattr(r, "original_router", None)
            if original_router is not None:
                _walk(original_router.routes)

    _walk(app.routes)
    return paths


def _strip(url: str) -> str:
    path = url.split("://", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else "/"
    return path.split("?", 1)[0]


def _install_fake_stripe(monkeypatch, calls):
    class _Session:
        id = "sess_123"
        url = "https://checkout.stripe.example/sess_123"

    class _FakeCheckoutSessionsService:
        def create(self, params=None, options=None):
            calls.append(dict(params or {}))
            return _Session()

    class _FakeV1:
        def __init__(self):
            self.checkout = types.SimpleNamespace(sessions=_FakeCheckoutSessionsService())

    class _FakeStripeClient:
        def __init__(self, api_key):
            self.v1 = _FakeV1()

    fake_stripe = types.ModuleType("stripe")
    fake_stripe.StripeClient = _FakeStripeClient
    monkeypatch.setitem(sys.modules, "stripe", fake_stripe)


def test_all_checkout_redirect_urls_resolve_to_registered_routes(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "rk_test_x")
    for plan, env in billing.PLAN_PRICE_ENV.items():
        monkeypatch.setenv(env, f"price_{plan}")

    calls = []
    _install_fake_stripe(monkeypatch, calls)
    registered = _registered_paths()

    base = "https://app.flightrecorder.example"
    for plan in billing.PLAN_PRICE_ENV:
        billing.create_checkout_session(
            plan,
            success_url=f"{base}/billing/success",
            cancel_url=f"{base}/billing/cancel",
        )

    assert calls, "no checkout sessions were created"
    urls = [c["success_url"] for c in calls] + [c["cancel_url"] for c in calls]
    for url in urls:
        path = _strip(url)
        assert path in registered, (
            f"Stripe redirect URL {url!r} resolves to path {path!r}, "
            f"which is not a registered route on the app"
        )
