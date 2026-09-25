# Flight Recorder vs Helicone

**Short version:** Helicone is an LLM gateway/observability product —
request logging, response caching, and cost analytics sitting in front of
your model calls. Flight Recorder is a tamper-evident audit trail. Helicone
tells you what a call cost and how fast it was; Flight Recorder proves a
record hasn't been altered since it was written.

## Pricing (Helicone's own published tier)

| Tier | Price |
|---|---|
| Pro | $79/mo |

Flight Recorder: free to self-host, or hosted Core $49/mo, Pro $149/mo,
Business $299/mo, unlimited seats.

*(Verify current Helicone pricing on their site before quoting.)*

## When Helicone is the better choice

- You want a drop-in gateway in front of your LLM calls that gives you
  caching (cuts real API spend on repeated prompts) plus cost/latency
  analytics with very little integration work.
- Your priority is reducing LLM bill and request logging for debugging,
  not producing evidence for a third party.
- You don't need an offline-verifiable signature chain — Helicone's logs
  living in their dashboard is enough for your use case.

## When Flight Recorder is the better choice

- You need to prove, to someone who doesn't trust your database, that a
  record existed at a given point and hasn't been modified since. Helicone
  logs are observability data, not signed evidence — there's no hash
  chain, no offline verifier, no out-of-band trusted key.
- You need a regulator export mapped to named frameworks (EU AI Act
  Art. 12, ISO/IEC 42001, FINRA 17a-4(f), SOC 2 CC7) rather than a
  dashboard export.
- You need crypto-shred (per-subject key destruction that makes that
  subject's payloads unreadable while the rest of the chain still
  verifies) for a right-to-erasure request without breaking chain
  integrity for everyone else.

## They can run together

Helicone's gateway/caching sits in the request path; Flight Recorder
instruments the client object, so both can wrap the same call:

```python
from flightrecorder import Recorder

rec = Recorder()
# my_openai_client here is already pointed at Helicone's proxy/base_url
# for caching + cost tracking; Flight Recorder just wraps the same client
# object to add the signed ledger on top.
client = rec.wrap_openai(my_openai_client)
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
```

Verify what actually got written, offline, independent of either vendor's
dashboard:

```bash
python -m flightrecorder.cli verify ./flightrecorder_ledger.jsonl
```
