"""Idempotent Stripe Products/Prices bootstrap for flightrecorder.

Reads STRIPE_SECRET_KEY from the environment and creates the Stripe
Products + Prices that flightrecorder's billing.py expects, one per tier in
TIERS below. Each Product carries metadata `app=flightrecorder` and
`tier=<name>` which is used to find-before-create on every run, so running
this script twice never creates duplicate Products or Prices.

Prints one `ENV_VAR=price_...` line per tier, ready to paste into `.env`.

If STRIPE_WEBHOOK_URL is set, also ensures a webhook endpoint exists for
that URL (find-before-create by URL) and, only when a NEW endpoint is
created, prints `STRIPE_WEBHOOK_SECRET=whsec_...` (Stripe only returns the
signing secret at creation time; if the endpoint already existed, rotate it
in the Stripe dashboard to get a fresh secret).

No third-party dependency is required: HTTP is done with the stdlib
`urllib` against api.stripe.com. Never hardcode a key — STRIPE_SECRET_KEY
must come from the environment.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.stripe.com/v1"

APP_NAME = "flightrecorder"

# tier -> (env var billing.py reads, unit amount in cents, "recurring" | "one_time")
TIERS: dict[str, tuple[str, int, str]] = {
    "core": ("STRIPE_PRICE_CORE", 4900, "recurring"),
    "pro": ("STRIPE_PRICE_PRO", 14900, "recurring"),
    "business": ("STRIPE_PRICE_BUSINESS", 29900, "recurring"),
}

WEBHOOK_EVENTS = [
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.paid",
    "invoice.payment_failed",
]


def _basic_auth_header(api_key: str) -> str:
    token = base64.b64encode(f"{api_key}:".encode()).decode()
    return f"Basic {token}"


def default_request(method: str, path: str, api_key: str, data: dict | None = None) -> dict:
    """Real HTTP call to the Stripe API. Injected as `request_fn` in tests
    so the test suite never touches the network."""
    url = f"{API_BASE}{path}"
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", _basic_auth_header(api_key))
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:  # pragma: no cover - network path
        raise RuntimeError(f"Stripe API error {exc.code}: {exc.read().decode()}") from exc


def find_product(request_fn, api_key: str, tier: str) -> dict | None:
    resp = request_fn("GET", "/products?limit=100&active=true", api_key)
    for product in resp.get("data", []):
        metadata = product.get("metadata", {})
        if metadata.get("app") == APP_NAME and metadata.get("tier") == tier:
            return product
    return None


def ensure_product(request_fn, api_key: str, tier: str) -> dict:
    existing = find_product(request_fn, api_key, tier)
    if existing is not None:
        return existing
    name = f"{APP_NAME} - {tier}"
    return request_fn(
        "POST",
        "/products",
        api_key,
        data={
            "name": name,
            "metadata[app]": APP_NAME,
            "metadata[tier]": tier,
        },
    )


def find_price(
    request_fn, api_key: str, product_id: str, amount_cents: int, recurring: bool
) -> dict | None:
    resp = request_fn("GET", f"/prices?product={product_id}&limit=100&active=true", api_key)
    for price in resp.get("data", []):
        if price.get("unit_amount") == amount_cents and bool(price.get("recurring")) == recurring:
            return price
    return None


def ensure_price(request_fn, api_key: str, product_id: str, amount_cents: int, kind: str) -> dict:
    recurring = kind == "recurring"
    existing = find_price(request_fn, api_key, product_id, amount_cents, recurring)
    if existing is not None:
        return existing
    data = {
        "product": product_id,
        "unit_amount": amount_cents,
        "currency": "usd",
    }
    if recurring:
        data["recurring[interval]"] = "month"
    return request_fn("POST", "/prices", api_key, data=data)


def bootstrap_prices(request_fn, api_key: str, tiers: dict | None = None) -> dict[str, str]:
    """Returns {env_var: price_id} for every tier, creating nothing that
    already exists (matched via Product metadata + Price amount/recurring)."""
    tiers = tiers if tiers is not None else TIERS
    results: dict[str, str] = {}
    for tier, (env_var, amount_cents, kind) in tiers.items():
        product = ensure_product(request_fn, api_key, tier)
        price = ensure_price(request_fn, api_key, product["id"], amount_cents, kind)
        results[env_var] = price["id"]
    return results


def find_webhook_endpoint(request_fn, api_key: str, url: str) -> dict | None:
    resp = request_fn("GET", "/webhook_endpoints?limit=100", api_key)
    for endpoint in resp.get("data", []):
        if endpoint.get("url") == url:
            return endpoint
    return None


def ensure_webhook_endpoint(request_fn, api_key: str, url: str) -> tuple[dict, str | None]:
    """Returns (endpoint, secret). secret is None when the endpoint already
    existed (Stripe never re-returns a signing secret after creation)."""
    existing = find_webhook_endpoint(request_fn, api_key, url)
    if existing is not None:
        return existing, None
    created = request_fn(
        "POST",
        "/webhook_endpoints",
        api_key,
        data={"url": url, "enabled_events[]": WEBHOOK_EVENTS},
    )
    return created, created.get("secret")


def main(argv: list[str] | None = None, request_fn=default_request) -> int:
    api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not api_key:
        print("STRIPE_SECRET_KEY is not set; nothing to do.", file=sys.stderr)
        return 1

    results = bootstrap_prices(request_fn, api_key)
    for env_var, price_id in results.items():
        print(f"{env_var}={price_id}")

    webhook_url = os.environ.get("STRIPE_WEBHOOK_URL")
    if webhook_url:
        _endpoint, secret = ensure_webhook_endpoint(request_fn, api_key, webhook_url)
        if secret:
            print(f"STRIPE_WEBHOOK_SECRET={secret}")
        else:
            print(
                "# webhook endpoint already existed for this URL; secret was not "
                "re-issued (rotate it in the Stripe dashboard if you need a new one)",
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
