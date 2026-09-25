# Flight Recorder

Evidence-grade, not just observability. Flight Recorder is a tamper-evident,
cryptographically signed, regulator-exportable audit trail for AI agents —
positioned against LLM-observability dashboards (Langfuse, Helicone,
Bifrost), which trace and debug but don't produce a defensible chain of
custody.

- **Hash-chained, Ed25519-signed ledger** — one fsync'd JSONL line per
  record, cross-process file-locked, never rewritten (`flightrecorder/ledger.py`).
- **Crypto-shred** — per-subject data keys wrapped by a KEK; destroying a
  subject's key makes its payloads permanently unreadable while the chain
  still verifies (`flightrecorder/crypto.py`).
- **Signed checkpoints** — periodic witness snapshots catch tail truncation
  a pure hash chain can't (`flightrecorder/checkpoint.py`).
- **Offline verifier** — `flightrecorder verify <ledger|export.zip|url>`
  requires an out-of-band trusted key for signature checks and never trusts
  a key bundled in the artifact it's verifying.
- **Regulator export pack** — `GET /v1/export` bundles records + signed
  checkpoints + the tenant's public key + `MAPPING.md` (field mapping to EU
  AI Act Art. 12, ISO/IEC 42001, FINRA 17a-4(f), SOC 2 CC7) into one zip.
- **Optional policy gate** — `flightrecorder.policy.Policy` (ported from
  an internal module) can evaluate allow/hold/block decisions and record the
  verdict into the ledger before an action runs.

## Quickstart (SDK, self-host, zero network calls)

```bash
pip install -e .
```

```python
from flightrecorder import Recorder

rec = Recorder()  # writes to ./flightrecorder_ledger.jsonl, no network
rec.record(kind="prompt", payload="what's the weather in Boston?")

@rec.tool
def lookup_weather(city: str) -> str:
    return f"72F in {city}"

lookup_weather("Boston")  # records tool_call + tool_result automatically

# Wrap any OpenAI-compatible client (real SDK or your own fake in tests —
# Flight Recorder never calls a provider itself, it only instruments
# whatever client object you hand it):
client = rec.wrap_openai(my_openai_client)
client.chat.completions.create(model="gpt-4o", messages=[...])
```

Verify the chain offline:

```bash
flightrecorder verify ./flightrecorder_ledger.jsonl
# OK: chain intact (N records)   -> exit 0
# TAMPERED: ...                  -> exit 2
```

## Hosted service

```bash
export FLIGHTRECORDER_KEK=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
export FLIGHTRECORDER_SIGNING_KEY=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
uvicorn flightrecorder.app:app --port 8015
```

For local development only, set `FLIGHTRECORDER_DEV=1` instead — ephemeral
random keys are generated per process and every record/export is stamped
`dev_mode: true` (never a valid audit trail; `flightrecorder verify` warns
and exits 3 on a dev-mode export .zip).

Create a tenant API key:

```python
from flightrecorder.auth import KeyStore
key = KeyStore("./data/api_keys.json").create_key("acme")
print(key)  # fr_live_... — shown once
```

### API

- `POST /v1/records` — ingest a normalized record. Returns `201` with
  `{seq, hash, ts, dev_mode}`.
- `POST /v1/otel` — ingest an OpenTelemetry GenAI-semantic-convention span
  (`gen_ai.request.model`, `gen_ai.prompt`, `gen_ai.completion`,
  `gen_ai.tool.*`).
- `GET /v1/verify` — verify the caller's tenant chain in-process.
- `GET /v1/export?format=jsonl|csv&from=&to=` — regulator pack (.zip):
  `records.jsonl` or `records.csv`, `chain_heads.json`, `anchors.jsonl`,
  `checkpoints.jsonl`, `public_key.hex`, `MAPPING.md`, `manifest.json`.

### Plan limits (enforced server-side, 429 on breach)

| Plan | Price | Records/month |
|---|---|---|
| Free (self-host) | $0 | 10,000 |
| Hosted Core | $49/mo | 100,000 |
| Pro | $149/mo | 1,000,000 |
| Business | $299/mo | 10,000,000, unlimited seats |

A 429 response includes an upgrade hint naming the next tier.

### Billing

`flightrecorder/billing.py` is safe-by-default: if `STRIPE_SECRET_KEY` +
`STRIPE_PRICE_CORE`/`PRO`/`BUSINESS` are all set, `POST /billing/checkout/
{plan}` creates a real Stripe Checkout session; else if `PAYMENT_LINK_URL`
is set, it redirects there; else it returns `503 payments not configured`.
`POST /stripe/webhook` verifies the signature against
`STRIPE_WEBHOOK_SECRET` and updates the tenant's plan on
`checkout.session.completed`. **No live Stripe products are created by this
repo** — set your own price IDs when you're ready to go live.

### Marketing pages

`/` (landing + pricing), `/compare/langfuse`, `/compare/helicone`,
`/compare/bifrost`, `/migrate/from-langfuse` — Jinja2-rendered, served by
`flightrecorder/web.py`.

## Stripe

- **Key management**: `STRIPE_SECRET_KEY` should be a **restricted key**
  (`rk_...`) scoped to only what this app needs (Checkout Sessions write,
  Billing Portal write, Customers read, Subscriptions read, Webhook
  Endpoints read) -- never a full secret key. In production, source it from
  **Google Secret Manager**, not a committed `.env`. `scripts/check_no_stripe_keys.py`
  (wired into `.pre-commit-config.yaml`) fails the build if a live/test
  secret is ever committed.
- **Bootstrap**: `python scripts/stripe_bootstrap.py` idempotently creates
  one Stripe Product per tier (core, pro, business) plus their Prices, and a
  webhook endpoint if `STRIPE_WEBHOOK_URL` is set.
- **Webhook events subscribed** (`POST /stripe/webhook`):
  `checkout.session.completed`, `checkout.session.async_payment_succeeded`,
  `checkout.session.async_payment_failed`, `customer.subscription.created`,
  `customer.subscription.updated`, `customer.subscription.deleted`,
  `invoice.paid`, `invoice.payment_failed`. Every event is signature-verified
  first (503 if unconfigured, 400 on failure) and idempotency-deduped by
  event id before any plan changes.
- **Customer Portal**: `POST /billing/portal?tenant=...` redirects a tenant
  with a stored Stripe customer id to the Stripe-hosted Customer Portal.
- **Tax**: enable Stripe Tax + register in each jurisdiction before charging
  US/EU customers -- `automatic_tax` is **not** enabled by default and
  Stripe silently collects no tax without an active registration.

## Docker

```bash
cp .env.example .env   # fill in FLIGHTRECORDER_KEK / FLIGHTRECORDER_SIGNING_KEY, or leave FLIGHTRECORDER_DEV=1
docker compose up --build
```

## Development

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate on Linux/Mac
pip install -e ".[dev,billing]"
pytest -q
ruff check .
```

## Field mapping / provenance

See `flightrecorder/mapping.py` (also embedded in every export bundle as
`MAPPING.md`) for how record fields map to EU AI Act Art. 12, ISO/IEC 42001,
FINRA 17a-4(f), and SOC 2 CC7. See `PROVENANCE.md` for exactly which files
in this repo were copied from an internal module/an internal module and what
changed.

## License

Apache-2.0 — see `LICENSE`.

## Live staging

https://flightrecorder-udrj5akpma-uc.a.run.app (Cloud Run, us-central1, project ripplarity-products (Ripplarity Inc), min-instances 0; ephemeral storage until a volume or Postgres is configured; Stripe not yet configured).
