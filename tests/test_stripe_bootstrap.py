"""Tests for scripts/stripe_bootstrap.py — fully mocked, no network."""

from __future__ import annotations

import itertools

import pytest

from scripts import stripe_bootstrap as sb


class FakeStripe:
    """In-memory stand-in for the Stripe API, enough to exercise
    find-before-create idempotency for products, prices, and webhook
    endpoints."""

    def __init__(self):
        self._id_counter = itertools.count(1)
        self.products: list[dict] = []
        self.prices: list[dict] = []
        self.webhook_endpoints: list[dict] = []
        self.calls: list[tuple[str, str]] = []

    def _next_id(self, prefix: str) -> str:
        return f"{prefix}_{next(self._id_counter)}"

    def __call__(self, method: str, path: str, api_key: str, data: dict | None = None) -> dict:
        assert api_key == "sk_test_fake"
        self.calls.append((method, path))
        base_path = path.split("?")[0]

        if method == "GET" and base_path == "/products":
            return {"data": list(self.products)}
        if method == "POST" and base_path == "/products":
            product = {
                "id": self._next_id("prod"),
                "name": data["name"],
                "metadata": {
                    "app": data["metadata[app]"],
                    "tier": data["metadata[tier]"],
                },
                "statement_descriptor": data.get("statement_descriptor"),
            }
            self.products.append(product)
            return product
        if method == "POST" and base_path.startswith("/products/"):
            product_id = base_path.split("/products/")[1]
            for product in self.products:
                if product["id"] == product_id:
                    product["statement_descriptor"] = data["statement_descriptor"]
                    return product
            raise AssertionError(f"unknown product {product_id}")

        if method == "GET" and base_path == "/prices":
            product_id = path.split("product=")[1].split("&")[0]
            return {"data": [p for p in self.prices if p["product"] == product_id]}
        if method == "POST" and base_path == "/prices":
            price = {
                "id": self._next_id("price"),
                "product": data["product"],
                "unit_amount": data["unit_amount"],
                "currency": data["currency"],
                "recurring": {"interval": data["recurring[interval]"]}
                if "recurring[interval]" in data
                else None,
            }
            self.prices.append(price)
            return price

        if method == "GET" and base_path == "/webhook_endpoints":
            return {"data": list(self.webhook_endpoints)}
        if method == "POST" and base_path == "/webhook_endpoints":
            endpoint = {
                "id": self._next_id("we"),
                "url": data["url"],
                "secret": self._next_id("whsec"),
            }
            self.webhook_endpoints.append(endpoint)
            return endpoint

        raise AssertionError(f"unexpected call: {method} {path}")


@pytest.fixture
def fake():
    return FakeStripe()


def test_bootstrap_creates_one_product_and_price_per_tier(fake):
    results = sb.bootstrap_prices(fake, "sk_test_fake")
    assert set(results.keys()) == {env for env, _, _ in sb.TIERS.values()}
    assert len(fake.products) == len(sb.TIERS)
    assert len(fake.prices) == len(sb.TIERS)


def test_bootstrap_is_idempotent_second_run_creates_nothing(fake):
    first = sb.bootstrap_prices(fake, "sk_test_fake")
    products_after_first = len(fake.products)
    prices_after_first = len(fake.prices)

    second = sb.bootstrap_prices(fake, "sk_test_fake")

    assert second == first
    assert len(fake.products) == products_after_first
    assert len(fake.prices) == prices_after_first


def test_webhook_endpoint_created_once_and_secret_only_printed_on_creation(fake):
    endpoint, secret = sb.ensure_webhook_endpoint(
        fake, "sk_test_fake", "https://example.com/webhook"
    )
    assert secret is not None
    assert endpoint["url"] == "https://example.com/webhook"

    endpoint2, secret2 = sb.ensure_webhook_endpoint(
        fake, "sk_test_fake", "https://example.com/webhook"
    )
    assert secret2 is None
    assert endpoint2["id"] == endpoint["id"]
    assert len(fake.webhook_endpoints) == 1


def test_main_requires_stripe_secret_key(monkeypatch, capsys):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    rc = sb.main(request_fn=lambda *a, **k: {})
    assert rc == 1
    err = capsys.readouterr().err
    assert "STRIPE_SECRET_KEY" in err


def test_main_prints_env_lines(monkeypatch, capsys, fake):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.delenv("STRIPE_WEBHOOK_URL", raising=False)
    rc = sb.main(request_fn=fake)
    assert rc == 0
    out = capsys.readouterr().out
    for env_var, _, _ in sb.TIERS.values():
        assert f"{env_var}=price_" in out


def test_main_prints_webhook_secret_when_url_given(monkeypatch, capsys, fake):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setenv("STRIPE_WEBHOOK_URL", "https://example.com/webhook")
    rc = sb.main(request_fn=fake)
    assert rc == 0
    out = capsys.readouterr().out
    assert "STRIPE_WEBHOOK_SECRET=whsec_" in out


def test_statement_descriptor_suffix_fits_stripe_budget():
    suffix = sb.STATEMENT_DESCRIPTOR_SUFFIX
    assert len(suffix) <= 15
    assert all(c.isalnum() or c == " " for c in suffix)
    assert not any(c in suffix for c in "<>\\'\"*")


def test_bootstrap_sets_statement_descriptor_on_created_products(fake):
    sb.bootstrap_prices(fake, "sk_test_fake")
    for product in fake.products:
        assert product["statement_descriptor"] == sb.STATEMENT_DESCRIPTOR_SUFFIX


def test_bootstrap_second_run_does_not_duplicate_products_and_stays_correct(fake):
    sb.bootstrap_prices(fake, "sk_test_fake")
    count_after_first = len(fake.products)

    for product in fake.products:
        product["statement_descriptor"] = None

    sb.bootstrap_prices(fake, "sk_test_fake")
    assert len(fake.products) == count_after_first
    for product in fake.products:
        assert product["statement_descriptor"] == sb.STATEMENT_DESCRIPTOR_SUFFIX
