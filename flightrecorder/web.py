"""Jinja2-rendered marketing pages: landing/pricing + honest competitor
comparisons + a migration guide. Mounted onto the main FastAPI app in
`flightrecorder/app.py`."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from . import billing
from . import plans as plans_mod

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def preview_mode_enabled() -> bool:
    """Default ON: shows a banner unless explicitly disabled with
    PREVIEW_MODE=0 once durable storage is attached."""
    return os.getenv("PREVIEW_MODE", "1") != "0"


templates.env.globals["preview_mode"] = preview_mode_enabled

PRICING = [
    {
        "name": "Free",
        "price": "$0",
        "period": "self-host",
        "limit": f"{plans_mod.PLAN_LIMITS['free']:,} records/mo",
        "plan": "free",
    },
    {
        "name": "Hosted Core",
        "price": "$49",
        "period": "/mo",
        "limit": f"{plans_mod.PLAN_LIMITS['core']:,} records/mo",
        "plan": "core",
    },
    {
        "name": "Pro",
        "price": "$149",
        "period": "/mo",
        "limit": f"{plans_mod.PLAN_LIMITS['pro']:,} records/mo",
        "plan": "pro",
    },
    {
        "name": "Business",
        "price": "$299",
        "period": "/mo",
        "limit": f"{plans_mod.PLAN_LIMITS['business']:,} records/mo, unlimited seats",
        "plan": "business",
    },
]

# Honest, sourced competitor numbers only — never invented.
COMPETITORS = {
    "langfuse": {
        "name": "Langfuse",
        "tiers": [
            ("Core", "$29/mo"),
            ("Pro", "$199/mo"),
            ("Enterprise", "$2,499/mo"),
        ],
        "positioning": "LLM observability/tracing platform.",
        "gap": (
            "Langfuse traces and evaluates LLM calls for debugging and quality; it is not "
            "built as evidence — there is no Ed25519-signed, hash-chained ledger, no "
            "crypto-shred, no offline out-of-band verifier, and no regulator export pack "
            "mapped to EU AI Act Art. 12 / ISO 42001 / FINRA 17a-4(f) / SOC 2 CC7."
        ),
    },
    "helicone": {
        "name": "Helicone",
        "tiers": [("Pro", "$79/mo")],
        "positioning": "LLM observability + gateway/caching.",
        "gap": (
            "Helicone focuses on request logging, caching, and cost analytics for LLM "
            "gateways. It is observability, not tamper-evidence: there is no cryptographic "
            "chain-of-custody or offline verifier producing a defensible audit artifact."
        ),
    },
    "bifrost": {
        "name": "Bifrost",
        "tiers": [("Audit-trail feature", "enterprise-only, no public price")],
        "positioning": "LLM gateway/router with an enterprise audit-trail add-on.",
        "gap": (
            "Bifrost's audit-trail capability is gated behind its enterprise tier with no "
            "published price — we don't guess a number here. FlightRecorder's tamper-evident "
            "ledger and regulator export are available from the Free self-host tier up."
        ),
    },
}


@router.get("/", response_class=HTMLResponse)
def landing(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "landing.html",
        {"pricing": PRICING, "stripe": billing.stripe_configured()},
    )


@router.get("/compare/langfuse", response_class=HTMLResponse)
def compare_langfuse(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "compare.html", {"competitor": COMPETITORS["langfuse"]}
    )


@router.get("/compare/helicone", response_class=HTMLResponse)
def compare_helicone(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "compare.html", {"competitor": COMPETITORS["helicone"]}
    )


@router.get("/compare/bifrost", response_class=HTMLResponse)
def compare_bifrost(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "compare.html", {"competitor": COMPETITORS["bifrost"]}
    )


@router.get("/migrate/from-langfuse", response_class=HTMLResponse)
def migrate_from_langfuse(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "migrate.html", {})


@router.get("/billing/success", response_class=HTMLResponse)
def billing_success(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "billing_success.html", {})


@router.get("/billing/cancel", response_class=HTMLResponse)
def billing_cancel(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "billing_cancel.html", {})
