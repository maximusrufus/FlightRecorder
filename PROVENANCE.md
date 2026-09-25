# Provenance

Flight Recorder is a standalone repo. It was bootstrapped by copying and
renaming code from two sibling local repos on this machine
(`Development/AgentRecord` and `Development/ActionFirewall`); there is no
Python import dependency on either — every file listed below was copied into
this repo and then edited in place.

## From `Development/AgentRecord/agentrecord/`

Package renamed `agentrecord` -> `flightrecorder` throughout (module paths,
env var prefix `AGENTRECORD_` -> `FLIGHTRECORDER_`, API key prefix
`ar_live_` -> `fr_live_`, docstrings, error strings).

| File (as copied) | Original path | Changes beyond the rename |
|---|---|---|
| `flightrecorder/__init__.py` | `agentrecord/__init__.py` | Rewrote docstring; now imports and re-exports the new `Recorder`/`RecorderError` SDK classes (AgentRecord's `__init__.py` exported nothing). |
| `flightrecorder/auth.py` | `agentrecord/auth.py` | Rename only. |
| `flightrecorder/crypto.py` | `agentrecord/crypto.py` | Rename only. |
| `flightrecorder/filelock.py` | `agentrecord/filelock.py` | Rename only. |
| `flightrecorder/ledger.py` | `agentrecord/ledger.py` | Rename only. |
| `flightrecorder/checkpoint.py` | `agentrecord/checkpoint.py` | Rename only. |
| `flightrecorder/anchor.py` | `agentrecord/anchor.py` | Rename only. |
| `flightrecorder/rfc3161_min.py` | `agentrecord/rfc3161_min.py` | Rename only. |
| `flightrecorder/proxy.py` | `agentrecord/proxy.py` | Rename; added plan-limit enforcement (`_check_plan_limit`, `plans.py` import) on `/v1/records` and `/v1/otel`; changed `/v1/records` to return HTTP 201 (was 200); extended `/v1/export` with a `format=jsonl|csv` query param and a `MAPPING.md` entry in the export bundle (new `mapping.py` import). |
| `flightrecorder/verify_cli.py` | `agentrecord/verify_cli.py` | Rename only — this remains the export-.zip verifier; the new top-level `flightrecorder verify` command (`cli.py`) is new code that dispatches to this for `.zip` targets. |

**Dropped** from the AgentRecord source (not copied — out of scope for this
build): `admin.py` (key-creation CLI convenience wrapper — key creation is
done directly via `KeyStore` in this repo's own scripts/tests) and
`rfc3161_verify.py` (full CMS/ASN.1 timestamp-authority certificate-chain
verification — the minimal RFC 3161 request/parse path in `rfc3161_min.py`
was kept; full CMS verification was judged out of scope for this pass).

**STATE.md check (per task instructions):** AgentRecord's `STATE.md` (frozen
2026-09-15, state "KILLED — market disproved, reuse as a sealing kernel") did
**not** flag any currently-broken behavior in the code itself — the kill
verdict was a market/positioning finding (S3 Object Lock + Cohasset
assessment already covers the incumbent seat), not a defect. No known bug was
carried forward.

## From `Development/ActionFirewall/action_firewall/`

| File (as copied) | Original path | Changes |
|---|---|---|
| `flightrecorder/policy.py` | `action_firewall/policy.py` | Core `Policy`/`Decision`/`ALLOW`/`HOLD`/`BLOCK` logic copied verbatim (no rename needed — no `action_firewall`-specific naming inside). Added a new method, `Policy.evaluate_and_record()`, that evaluates a policy and appends the verdict into a `flightrecorder.ledger.Ledger` as a `tool_result` record — this is new code, not present in ActionFirewall, added so a pre-action policy gate's decision becomes part of the tamper-evident audit trail. |

`action_firewall/firewall.py`, `mcp_server.py`, and `reporter.py` were **not**
copied — only the deterministic rule-evaluation core (`policy.py`) was
in scope for the "optional pre-action gate" feature.

## New code (no prior-repo source)

`flightrecorder/recorder.py` (SDK: `Recorder`, `@rec.tool`, `wrap_openai`),
`flightrecorder/cli.py` (`flightrecorder verify` command), `flightrecorder/
plans.py` (plan/usage tracking), `flightrecorder/mapping.py` (regulator
field-mapping doc generator), `flightrecorder/billing.py` (Stripe
integration), `flightrecorder/web.py` + `flightrecorder/templates/*.html`
(marketing/pricing pages), `flightrecorder/app.py` (top-level ASGI app
wiring), plus all files under `tests/test_recorder_sdk.py`,
`tests/test_cli_verify.py`, `tests/test_policy.py`, `tests/test_plans.py`,
`tests/test_export_and_plans.py`, `tests/test_billing.py`.

## Tests ported from AgentRecord's `tests/`

All of `_concurrent_worker.py`, `_test_ca.py`, `conftest.py`,
`test_attacks.py`, `test_auth.py`, `test_checkpoint.py`,
`test_concurrent_append.py`, `test_crypto_shred.py`, `test_dev_mode.py`,
`test_key_rotation.py`, `test_ledger_basic.py`, `test_proxy_api.py`,
`test_size_cap.py`, `test_startup_refusal.py` were copied and renamed
(`agentrecord` -> `flightrecorder`), then adjusted for two proxy.py
behavior changes made in this repo: `/v1/records` now returns 201 (was
200), and every proxy-app test fixture now also monkeypatches
`PLANS_PATH`/resets `proxy_mod._plans` so plan-limit enforcement doesn't
leak real on-disk state between test runs. `test_anchor.py` and
`test_rfc3161_verify.py` were dropped along with the features they cover
(see above). Two `E741` lint fixes (ambiguous variable name `l` -> `ln`)
were applied to `test_checkpoint.py` and `test_ledger_basic.py` for
`ruff check .` cleanliness — no behavioral change.
