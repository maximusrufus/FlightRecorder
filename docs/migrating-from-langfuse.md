# Migrating from Langfuse

Most teams shouldn't fully migrate off Langfuse — its trace viewer, evals,
and prompt playground solve a real problem Flight Recorder doesn't touch.
This guide is for the narrower case: you need a tamper-evident audit trail
*in addition to* (or, for the subset of teams that only ever used Langfuse
for compliance logging and never touched its debugging UI, *instead of*)
Langfuse.

## 1. Decide: alongside, or instead of

- **Keep Langfuse if** anyone on your team opens its trace viewer, runs
  evals, or uses prompt versioning. Add Flight Recorder next to it for the
  evidence requirement; see step 2.
- **Replace Langfuse if** you were only using it to have *some* record of
  what the agent did, and the debugging UI was never the point. Flight
  Recorder's ledger is a strictly stronger record (signed, hash-chained,
  offline-verifiable) — it's just not a dashboard.

## 2. Wrap the same client

Langfuse instruments via a callback handler; Flight Recorder instruments
by wrapping the client object directly. Both can point at the same
`client`:

```python
from flightrecorder import Recorder

rec = Recorder()  # writes ./flightrecorder_ledger.jsonl locally, no network

# your_openai_client already has Langfuse's callback/handler wired in,
# however your integration does that (decorator, base_url, etc.) —
# Flight Recorder just wraps the resulting client object:
client = rec.wrap_openai(your_openai_client)

client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "hi"}],
)
# This call is now traced by Langfuse (if still wired) AND recorded as a
# signed, hash-chained record by Flight Recorder.
```

## 3. Understand the storage model difference

Langfuse traces are rows in a Postgres table your own application (or a
sufficiently privileged operator) can update or delete. Flight Recorder
records are appended to a JSONL ledger where each line is hash-chained to
the previous one and Ed25519-signed
(`flightrecorder/ledger.py`) — there is no update or delete path in the
library at all; `crypto-shred` (destroying a subject's data key) is the
only supported way to make a specific subject's data unreadable, and even
after a shred the surrounding chain and signatures still verify.

Prove that offline, without trusting Flight Recorder's own server:

```bash
python -m flightrecorder.cli verify ./flightrecorder_ledger.jsonl
# OK: chain intact (N records)   -> exit 0
# TAMPERED: ...                  -> exit 2
```

## 4. Swap your export step

Where you previously pulled a Langfuse dataset export or database dump for
an auditor, use the regulator export pack instead:

```bash
curl -H "Authorization: Bearer $FLIGHTRECORDER_API_KEY" \
  "https://your-flightrecorder-host/v1/export?format=jsonl" \
  -o export.zip
```

`export.zip` contains `records.jsonl`, `chain_heads.json`,
`anchors.jsonl`, `checkpoints.jsonl`, `public_key.hex`, and `MAPPING.md`
(the field-level cross-reference to EU AI Act Art. 12, ISO/IEC 42001,
FINRA 17a-4(f), SOC 2 CC7) — hand the whole zip to whoever needs it; they
can run `flightrecorder verify export.zip --trusted-key <hex>` themselves
without needing access to your infrastructure.

## 5. What you lose

No trace viewer, no session replay, no LLM-as-judge evals, no prompt
playground. If you use any of those day to day, keep Langfuse running
alongside Flight Recorder rather than dropping it — see
`docs/flightrecorder-vs-langfuse.md` for the fuller comparison.
