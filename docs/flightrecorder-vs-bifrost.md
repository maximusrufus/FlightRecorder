# Flight Recorder vs Bifrost

**Short version:** Bifrost is an LLM gateway/router; it has an audit-trail
feature, but it's gated behind Bifrost's enterprise tier with no published
price. Flight Recorder's tamper-evident ledger and regulator export are
available starting at the free self-host tier.

## Pricing

Bifrost's audit-trail capability: enterprise-only, no public price — we
don't guess a number here; contact Bifrost directly if that's the feature
you need from them.

Flight Recorder: free to self-host (every feature, including the signed
ledger, offline verifier, and regulator export — the paid hosted tiers are
about *not running your own server*, not about unlocking audit
capability), or hosted Core $49/mo, Pro $149/mo, Business $299/mo,
unlimited seats.

## When Bifrost is the better choice

- You primarily need a multi-provider LLM gateway/router — unified API
  across providers, load balancing, failover — and an audit trail is a
  nice-to-have you're willing to pay enterprise pricing for once you need
  it.
- You're already standardized on Bifrost for routing and don't want a
  second piece of infrastructure in the request path.

## When Flight Recorder is the better choice

- You want the tamper-evident audit capability itself — hash chain,
  Ed25519 signatures, offline verifier, regulator export mapped to EU AI
  Act Art. 12 / ISO 42001 / FINRA 17a-4(f) / SOC 2 CC7 — without an
  enterprise sales conversation, starting from the free self-host tier.
- You want the audit layer decoupled from your gateway/routing choice.
  Flight Recorder doesn't route model calls at all; it wraps whatever
  client object you hand it (including a client already pointed at
  Bifrost), so switching gateways later doesn't mean losing your audit
  history.

```python
from flightrecorder import Recorder

rec = Recorder()
# my_openai_client can be pointed at Bifrost (or any OpenAI-compatible
# gateway) — Flight Recorder only instruments the client, it never makes
# the provider call itself.
client = rec.wrap_openai(my_openai_client)
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
```

```bash
# Independent of whichever gateway routed the call, verify what Flight
# Recorder actually chained and signed:
python -m flightrecorder.cli verify ./flightrecorder_ledger.jsonl
```
