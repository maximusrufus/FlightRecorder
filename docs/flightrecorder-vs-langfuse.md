# Flight Recorder vs Langfuse

**Short version:** Langfuse is an LLM observability platform (tracing,
evals, prompt management, cost/latency dashboards). Flight Recorder is a
tamper-evident audit trail (hash-chained, Ed25519-signed ledger + offline
verifier + regulator export). They solve different problems and many teams
run both.

## Pricing (Langfuse's own published tiers)

| Tier | Price |
|---|---|
| Core | $29/mo |
| Pro | $199/mo |
| Enterprise | $2,499/mo |

Flight Recorder: free to self-host (Apache-2.0), or hosted Core $49/mo,
Pro $149/mo, Business $299/mo — unlimited seats on every hosted tier.

*(Verify current Langfuse pricing on their site before quoting — this is a
snapshot, not a live feed.)*

## When Langfuse is the better choice

- You want to debug why a chain produced a bad output — Langfuse's trace
  viewer, session replay, and prompt playground are built for exactly
  that, and Flight Recorder has no UI for it at all.
- You want LLM-as-judge evals, dataset-based regression testing, or
  prompt versioning with a diff view.
- You don't have a regulator, auditor, or opposing counsel in the
  picture — you just want to know why the agent did what it did.

Flight Recorder is not a Langfuse replacement for any of the above.

## When Flight Recorder is the better choice

- Something downstream (a regulator, an auditor, a court) will ask "prove
  this log wasn't edited after it was written." Langfuse traces are
  mutable rows in a database table your own application can update;
  Flight Recorder records are hash-chained and Ed25519-signed, and
  `flightrecorder verify` checks that chain against an out-of-band
  trusted key it never takes from the artifact being verified.
- You need per-subject "crypto-shred" — destroying one person's data key
  so their payloads become permanently unreadable while every other
  record's chain and signatures still verify (`flightrecorder/crypto.py`).
- You need to hand someone a self-contained regulator export: records +
  signed checkpoints + public key + `MAPPING.md` (a field-level
  cross-reference to EU AI Act Art. 12, ISO/IEC 42001, FINRA 17a-4(f),
  SOC 2 CC7) in one zip, rather than a database dump.

## Running both together

They're not mutually exclusive — instrument the same call site with both
and use each for what it's good at:

```python
from flightrecorder import Recorder

rec = Recorder()  # Flight Recorder: evidence layer

# ... your existing Langfuse callback/handler stays wired to the same
# client for tracing/debugging ...

client = rec.wrap_openai(my_openai_client)
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
# Now the call is both traced (Langfuse) and chained into a signed,
# offline-verifiable ledger (Flight Recorder).
```

See `docs/migrating-from-langfuse.md` if you're deciding whether to
replace Langfuse outright rather than run alongside it (short answer: for
most teams, don't — keep it for tracing, add Flight Recorder for
evidence).
