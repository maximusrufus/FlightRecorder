"""Stripe billing integration — safe by default.

Behavior, in priority order:
  1. If STRIPE_SECRET_KEY + STRIPE_PRICE_CORE/PRO/BUSINESS are ALL set,
     create a real Stripe Checkout session via the `stripe` package.
  2. Else if PAYMENT_LINK_URL is set, return a redirect to it.
  3. Else, return a "payments not configured" response.

`/stripe/webhook` verifies the signature against STRIPE_WEBHOOK_SECRET and,
on `checkout.session.completed`, updates the tenant's plan via
`flightrecorder.plans.PlanStore`.

No real Stripe API call is ever made from this module's own test suite —
tests monkeypatch/mock the `stripe` import entirely. This module never
imports `stripe` at module load time (imported lazily inside functions) so
the package can be installed and run with zero Stripe dependency present.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import plans as plans_mod

router = APIRouter()

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


def create_checkout_session(plan: str, *, success_url: str, cancel_url: str) -> dict[str, Any]:
    """Returns {"mode": "stripe", "url": ...} | {"mode": "payment_link", "url": ...}
    | {"mode": "unconfigured"}. Never raises for the unconfigured case."""
    if plan not in PLAN_PRICE_ENV:
        raise HTTPException(400, f"unknown plan {plan!r}; expected one of {list(PLAN_PRICE_ENV)}")

    if stripe_configured():
        import stripe  # lazy import — only touched when actually configured

        stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
        price_id = os.environ[PLAN_PRICE_ENV[plan]]
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return {"mode": "stripe", "url": session.url}

    if payment_link_configured():
        return {"mode": "payment_link", "url": os.environ["PAYMENT_LINK_URL"]}

    return {"mode": "unconfigured"}


@router.post("/billing/checkout/{plan}", response_model=None)
def checkout(plan: str, request: Request) -> JSONResponse | RedirectResponse:
    base = str(request.base_url).rstrip("/")
    result = create_checkout_session(
        plan,
        success_url=f"{base}/billing/success",
        cancel_url=f"{base}/billing/cancel",
    )
    if result["mode"] == "unconfigured":
        return JSONResponse({"error": "payments not configured", "plan": plan}, status_code=503)
    return RedirectResponse(result["url"], status_code=303)


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


@router.post("/stripe/webhook")
async def stripe_webhook(
    request: Request, stripe_signature: Optional[str] = Header(default=None)
) -> dict[str, Any]:
    payload = await request.body()
    event = _verify_stripe_signature(payload, stripe_signature)

    if event.get("type") == "checkout.session.completed":
        session = event["data"]["object"]
        tenant = session.get("client_reference_id") or session.get("customer")
        plan = _plan_from_session(session)
        if tenant and plan:
            store = plans_mod.PlanStore(
                os.path.join(os.getenv("FLIGHTRECORDER_DATA_DIR", "./data"), "plans.json")
            )
            store.set_plan(tenant, plan)

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
