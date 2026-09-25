# Show HN draft (NOT posted — local draft only)

## Title (under 80 chars)

Show HN: Flight Recorder – tamper-evident, signed audit trail for AI agents

(76 characters)

## First comment (150-250 words, HN plain register)

Hi HN. I built Flight Recorder because every "AI observability" tool I
looked at logs to a mutable database table, which is fine for debugging
but doesn't hold up if someone later asks "prove this wasn't edited."

It's a small library + optional hosted service: every record (prompt,
output, tool call) is Ed25519-signed and hash-chained to the one before
it, one fsync'd JSONL line at a time, never rewritten. An offline verifier
checks the chain against a trusted key you supply out-of-band — it never
trusts a key bundled in the file it's checking. There's a regulator export
that bundles records, signed checkpoints, and a field-mapping doc
(EU AI Act Art. 12 / ISO 42001 / FINRA 17a-4(f) / SOC 2 CC7 — a
cross-reference, not a legal opinion) into one zip.

What it does NOT do: tracing UI, prompt evals, LLM-as-judge, gateway
caching — if that's what you need, Langfuse or Helicone are better tools
and I say so in the docs.

Known limitations, stated plainly:
- The hosted preview (Cloud Run, scale-to-zero) writes to container-local
  disk, so it does **not** survive a redeploy or a scale-to-zero cycle
  yet — durable storage (a mounted volume or Postgres) isn't wired up in
  the hosted preview yet, so treat it as a demo, not somewhere to point
  real audit data. Self-hosting with a mounted volume works today.
- No Stripe products are live yet; billing code exists but nothing is for
  sale.
- Regulator field-mapping is a documented cross-reference I wrote myself,
  not a legal certification — I'd like feedback from anyone who's actually
  built to 17a-4(f) or EU AI Act Art. 12 on whether the mapping is sound.

Apache-2.0, self-hostable, source: github.com/maximusrufus/FlightRecorder.
Would especially like feedback on whether the crypto-shred design (per-
subject key destruction) is the right shape for GDPR-style erasure
requests without breaking chain integrity for everyone else.
