"""Pins our fake Stripe client's contract to the REAL SDK's contract.

`stripe.StripeClient(...).v1.checkout.sessions.create` (and the
billing_portal equivalent) take a single positional `params` dict, not
`**kwargs`. Our hand-written test fakes must match that signature, or the
tests are green against the wrong contract and only fail against a live
Stripe sandbox.

Imports the real `stripe` SDK only -- no network call, no API key needed.
"""

from __future__ import annotations

import inspect

import pytest

from tests.test_billing import _install_fake_stripe_module


def test_real_sdk_checkout_sessions_create_is_positional_params():
    from stripe.checkout._session_service import SessionService

    params = list(inspect.signature(SessionService.create).parameters)
    assert params[:3] == ["self", "params", "options"]


def test_real_sdk_billing_portal_sessions_create_is_positional_params():
    from stripe.billing_portal._session_service import SessionService

    params = list(inspect.signature(SessionService.create).parameters)
    assert params[:3] == ["self", "params", "options"]


def test_fake_checkout_sessions_create_accepts_positional_dict(monkeypatch):
    fake = _install_fake_stripe_module(monkeypatch)
    client = fake.StripeClient("sk_test")
    session = client.v1.checkout.sessions.create({"mode": "subscription"})
    assert session.url == "https://checkout.stripe.com/fake-session"


def test_fake_checkout_sessions_create_rejects_kwargs(monkeypatch):
    """If someone reverts the fake back to `def create(**kwargs)`, this must
    fail: the real SDK does not accept `mode=...` as a keyword argument."""
    fake = _install_fake_stripe_module(monkeypatch)
    client = fake.StripeClient("sk_test")
    with pytest.raises(TypeError):
        client.v1.checkout.sessions.create(mode="subscription")


def test_fake_portal_sessions_create_accepts_positional_dict(monkeypatch):
    fake = _install_fake_stripe_module(monkeypatch)
    client = fake.StripeClient("sk_test")
    session = client.v1.billing_portal.sessions.create({"customer": "cus_1"})
    assert session.url == "https://billing.stripe.com/fake-portal"


def test_fake_portal_sessions_create_rejects_kwargs(monkeypatch):
    fake = _install_fake_stripe_module(monkeypatch)
    client = fake.StripeClient("sk_test")
    with pytest.raises(TypeError):
        client.v1.billing_portal.sessions.create(customer="cus_1")
