"""Stripe billing integration — safe by default.

Behavior, in priority order:
  1. If STRIPE_SECRET_KEY + STRIPE_PRICE_CORE/PRO/BUSINESS are ALL set,
     create a real Stripe Checkout session via `stripe.StripeClient` (never
     the deprecated global `stripe.api_key = ...` pattern). `STRIPE_SECRET_KEY`
     should be a **restricted key** (`rk_...`) scoped to the minimum
     permissions this app needs; in production it must come from Secret
     Manager, never a committed `.env`.
  2. Else if PAYMENT_LINK_URL is set, return a redirect to it.
  3. Else, return a "payments not configured" response.

`/stripe/webhook` verifies the signature against STRIPE_WEBHOOK_SECRET,
dedupes by event id, and handles checkout completion + the full
subscription lifecycle (created/updated/deleted, invoice paid/failed),
updating the tenant's plan via `flightrecorder.plans.PlanStore`.

No real Stripe API call is ever made from this module's own test suite —
tests monkeypatch/mock the `stripe` import entirely. This module never
imports `stripe` at module load time (imported lazily inside functions) so
the package can be installed and run with zero Stripe dependency present.
"""

from __future__ import annotations

import os
import random
import string
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import plans as plans_mod

router = APIRouter()

APP_NAME = "flightrecorder"

PLAN_PRICE_ENV = {
    "core": "STRIPE_PRICE_CORE",
    "pro": "STRIPE_PRICE_PRO",
    "business": "STRIPE_PRICE_BUSINESS",
}


def stripe_configured() -> bool:
    if not os.getenv("STRIPE_SECRET_KEY"):
        return False
    return all(os.getenv(env) for env in PLAN_PRICE_ENV.values())


def payment_link_configured() -> bool:
    return bool(os.getenv("PAYMENT_LINK_URL"))


def _plans_store() -> plans_mod.PlanStore:
    return plans_mod.PlanStore(
        os.path.join(os.getenv("FLIGHTRECORDER_DATA_DIR", "./data"), "plans.json")
    )


def _integration_identifier(flow: str) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{APP_NAME}-{flow}-{suffix}"


def get_client():
    """Instantiate a `StripeClient` from `STRIPE_SECRET_KEY`."""
    import stripe  # lazy import — only touched when actually configured

    return stripe.StripeClient(os.environ["STRIPE_SECRET_KEY"])


def create_checkout_session(
    plan: str,
    *,
    success_url: str,
    cancel_url: str,
    tenant: str | None = None,
    customer_email: str | None = None,
) -> dict[str, Any]:
    """Returns {"mode": "stripe", "url": ...} | {"mode": "payment_link", "url": ...}
    | {"mode": "unconfigured"}. Never raises for the unconfigured case."""
    if plan not in PLAN_PRICE_ENV:
        raise HTTPException(400, f"unknown plan {plan!r}; expected one of {list(PLAN_PRICE_ENV)}")

    if stripe_configured():
        client = get_client()
        price_id = os.environ[PLAN_PRICE_ENV[plan]]
        params: dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "integration_identifier": _integration_identifier(plan),
            "subscription_data": {"metadata": {"plan": plan, "tenant": tenant or ""}},
        }
        if tenant:
            params["client_reference_id"] = tenant
        if customer_email:
            params["customer_email"] = customer_email
        session = client.v1.checkout.sessions.create(params)
        return {"mode": "stripe", "url": session.url}

    if payment_link_configured():
        return {"mode": "payment_link", "url": os.environ["PAYMENT_LINK_URL"]}

    return {"mode": "unconfigured"}


@router.post("/billing/checkout/{plan}", response_model=None)
def checkout(plan: str, request: Request) -> JSONResponse | RedirectResponse:
    base = str(request.base_url).rstrip("/")
    tenant = request.query_params.get("tenant")
    customer_email = request.query_params.get("customer_email")
    result = create_checkout_session(
        plan,
        success_url=f"{base}/billing/success",
        cancel_url=f"{base}/billing/cancel",
        tenant=tenant,
        customer_email=customer_email,
    )
    if result["mode"] == "unconfigured":
        return JSONResponse({"error": "payments not configured", "plan": plan}, status_code=503)
    return RedirectResponse(result["url"], status_code=303)


@router.post("/billing/portal", response_model=None)
def billing_portal(request: Request) -> JSONResponse | RedirectResponse:
    tenant = request.query_params.get("tenant")
    if not tenant:
        raise HTTPException(400, "tenant is required")
    store = _plans_store()
    customer_id = store.get_stripe_customer_id(tenant)
    if not customer_id:
        raise HTTPException(404, "no Stripe customer for tenant")
    client = get_client()
    base = str(request.base_url).rstrip("/")
    session = client.v1.billing_portal.sessions.create(
        {
            "customer": customer_id,
            "return_url": f"{base}/billing/portal-return",
        }
    )
    return RedirectResponse(session.url, status_code=303)


def _verify_stripe_signature(payload: bytes, sig_header: Optional[str]) -> dict[str, Any]:
    import stripe  # lazy import

    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(503, "STRIPE_WEBHOOK_SECRET not configured")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except Exception as exc:  # invalid payload or signature
        raise HTTPException(400, f"invalid webhook signature: {exc}") from exc
    return event


def _session_tenant(session: dict[str, Any]) -> Optional[str]:
    tenant = session.get("client_reference_id")
    if tenant:
        return tenant
    metadata = session.get("metadata") or {}
    return metadata.get("tenant") or None


def _fulfill_checkout_session(store: plans_mod.PlanStore, session: dict[str, Any]) -> None:
    """Only called after `payment_status != 'unpaid'` is confirmed."""
    tenant = _session_tenant(session)
    plan = _plan_from_session(session)
    if tenant and plan:
        store.set_plan(tenant, plan)
    customer_id = session.get("customer")
    if tenant and customer_id:
        store.set_stripe_customer(tenant, customer_id)


def _handle_subscription_event(
    store: plans_mod.PlanStore, event_type: str, obj: dict[str, Any]
) -> None:
    customer_id = obj.get("customer")
    if not customer_id:
        return
    tenant = store.resolve_tenant_by_customer_id(customer_id)
    if not tenant:
        return
    if event_type == "customer.subscription.deleted":
        store.set_subscription_state(tenant, obj.get("id"), "canceled")
        store.downgrade(tenant)
        return
    status = obj.get("status")
    store.set_subscription_state(tenant, obj.get("id"), status)
    if event_type == "invoice.payment_failed":
        store.downgrade(tenant)


@router.post("/stripe/webhook")
async def stripe_webhook(
    request: Request, stripe_signature: Optional[str] = Header(default=None)
) -> dict[str, Any]:
    payload = await request.body()
    event = _verify_stripe_signature(payload, stripe_signature)

    store = _plans_store()
    event_id = event.get("id") or ""
    event_type = event.get("type", "")
    if event_id and not store.mark_event_processed(event_id):
        return {"received": True, "duplicate": True}

    obj = event.get("data", {}).get("object", {})

    if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        if obj.get("payment_status") != "unpaid":
            _fulfill_checkout_session(store, obj)
    elif event_type in (
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ):
        _handle_subscription_event(store, event_type, obj)
    elif event_type == "invoice.paid":
        subscription_id = obj.get("subscription")
        if subscription_id:
            _handle_subscription_event(
                store,
                event_type,
                {"customer": obj.get("customer"), "id": subscription_id, "status": "active"},
            )
    elif event_type == "invoice.payment_failed":
        subscription_id = obj.get("subscription")
        if subscription_id:
            _handle_subscription_event(
                store,
                event_type,
                {"customer": obj.get("customer"), "id": subscription_id, "status": "past_due"},
            )

    return {"received": True}


def _plan_from_session(session: dict[str, Any]) -> Optional[str]:
    """Best-effort: read a `metadata.plan` field set at Checkout-session
    creation time, falling back to matching the line-item price id against
    the configured STRIPE_PRICE_* env vars."""
    metadata = session.get("metadata") or {}
    if metadata.get("plan") in PLAN_PRICE_ENV:
        return metadata["plan"]
    price_id = session.get("price_id") or (session.get("display_items") or [{}])[0].get(
        "price", {}
    ).get("id")
    for plan, env in PLAN_PRICE_ENV.items():
        if price_id and os.getenv(env) == price_id:
            return plan
    return None
