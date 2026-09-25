"""FastAPI ingest/export/verify service for FlightRecorder.

Endpoints:
  POST /v1/records         — direct ingest of a normalized record.
  POST /v1/otel            — ingest an OpenTelemetry GenAI-semantic-
                              convention span and translate it into ledger
                              record(s).
  GET  /v1/export           — examiner export: a zip of records + chain
                              heads + anchors + checkpoints + public key.
  GET  /v1/verify           — verify the ledger in-process.

AUTH (2026-09-13 hardening): every endpoint requires
`Authorization: Bearer <api-key>`. The tenant is DERIVED from the key via
`flightrecorder.auth.KeyStore` — it is NEVER taken from the request body. If a
request body includes a `tenant` field that does not match the caller's
key-derived tenant, the request is refused with 403 (this catches a caller
trying to write into or read someone else's tenant by simply naming it).
Export/verify are always scoped to the caller's own tenant.

KEY STARTUP CHECK: importing this module calls `crypto._kek()` and
`crypto._private_key()` eagerly (not lazily on first request) so a
misconfigured deployment (`FLIGHTRECORDER_KEK`/`FLIGHTRECORDER_SIGNING_KEY`
missing, `FLIGHTRECORDER_DEV` unset) fails at process start with a clear
error, not silently on the first API call.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import anchor as anchor_mod
from . import checkpoint as checkpoint_mod
from . import crypto
from . import ledger as ledger_mod
from . import mapping as mapping_mod
from . import plans as plans_mod
from .auth import KeyStore

DATA_DIR = os.getenv("FLIGHTRECORDER_DATA_DIR", "./data")
LEDGER_PATH = os.path.join(DATA_DIR, "ledger.jsonl")
ANCHOR_PATH = os.path.join(DATA_DIR, "anchors.jsonl")
KEYS_PATH = os.path.join(DATA_DIR, "api_keys.json")
PLANS_PATH = os.path.join(DATA_DIR, "plans.json")
WITNESS_DIR = os.getenv("FLIGHTRECORDER_WITNESS_DIR", os.path.join(DATA_DIR, "witness"))

# Fail fast: refuse to start without real key material (or an explicit
# FLIGHTRECORDER_DEV=1 opt-in to ephemeral random keys). Raises
# crypto.KeyConfigError, a RuntimeError subclass, if misconfigured.
crypto._kek()
crypto._private_key()

app = FastAPI(title="FlightRecorder", version="0.2.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


_ledger: Optional[ledger_mod.Ledger] = None
_anchors: Optional[anchor_mod.AnchorStore] = None
_keystore: Optional[KeyStore] = None
_witness: Optional[checkpoint_mod.CheckpointWitness] = None
_scheduler = checkpoint_mod.CheckpointScheduler()


def get_ledger() -> ledger_mod.Ledger:
    global _ledger
    if _ledger is None:
        _ledger = ledger_mod.Ledger(LEDGER_PATH)
    return _ledger


def get_anchor_store() -> anchor_mod.AnchorStore:
    global _anchors
    if _anchors is None:
        _anchors = anchor_mod.AnchorStore(ANCHOR_PATH)
    return _anchors


def get_key_store() -> KeyStore:
    global _keystore
    if _keystore is None:
        _keystore = KeyStore(KEYS_PATH)
    return _keystore


def get_witness() -> checkpoint_mod.CheckpointWitness:
    global _witness
    if _witness is None:
        _witness = checkpoint_mod.CheckpointWitness(WITNESS_DIR)
    return _witness


_plans: Optional[plans_mod.PlanStore] = None


def get_plan_store() -> plans_mod.PlanStore:
    global _plans
    if _plans is None:
        _plans = plans_mod.PlanStore(PLANS_PATH)
    return _plans


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def require_tenant(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing Authorization: Bearer <api-key> header")
    raw_key = authorization.split(" ", 1)[1].strip()
    tenant = get_key_store().tenant_for_key(raw_key)
    if tenant is None:
        raise HTTPException(401, "invalid API key")
    return tenant


def _check_body_tenant(body_tenant: Optional[str], auth_tenant: str) -> None:
    if body_tenant is not None and body_tenant != auth_tenant:
        raise HTTPException(
            403,
            f"tenant mismatch: API key belongs to {auth_tenant!r}, "
            f"request body named {body_tenant!r}",
        )


def _check_plan_limit(tenant: str, n: int = 1) -> None:
    try:
        get_plan_store().check_and_increment(tenant, n)
    except plans_mod.PlanLimitExceeded as exc:
        raise HTTPException(429, str(exc)) from exc


def _emit_checkpoint(tenant: str, result: ledger_mod.AppendResult) -> None:
    checkpoint_mod.emit_checkpoint_if_due(
        _scheduler,
        get_witness(),
        tenant=tenant,
        head_seq=result.seq,
        head_hash=result.hash,
        attempt_tsa=False,  # API path: don't block requests on network TSA calls
    )


# ---------------------------------------------------------------------------
# /v1/records — direct ingest
# ---------------------------------------------------------------------------


class RecordIn(BaseModel):
    tenant: Optional[str] = None  # optional; must match the caller's key if present
    agent_id: str
    model: str
    model_version: str
    kind: str = Field(..., description="prompt|output|tool_call|tool_result")
    payload: str = Field(..., description="raw text/JSON payload, plaintext")
    subject_id: Optional[str] = None


class RecordOut(BaseModel):
    seq: int
    hash: str
    ts: str
    dev_mode: bool = False


@app.post("/v1/records", response_model=RecordOut, status_code=201)
def ingest_record(rec: RecordIn, tenant: str = Depends(require_tenant)) -> RecordOut:
    _check_body_tenant(rec.tenant, tenant)
    if rec.kind not in ledger_mod.VALID_KINDS:
        raise HTTPException(400, f"invalid kind {rec.kind!r}")

    payload_bytes = rec.payload.encode("utf-8")
    if len(payload_bytes) > ledger_mod.max_payload_bytes():
        raise HTTPException(413, "payload exceeds FLIGHTRECORDER_MAX_PAYLOAD_BYTES")

    _check_plan_limit(tenant)

    result = get_ledger().append(
        tenant=tenant,
        agent_id=rec.agent_id,
        model=rec.model,
        model_version=rec.model_version,
        kind=rec.kind,
        payload=payload_bytes,
        subject_id=rec.subject_id,
    )
    _emit_checkpoint(tenant, result)
    return RecordOut(
        seq=result.seq,
        hash=result.hash,
        ts=result.record["ts"],
        dev_mode=result.record["dev_mode"],
    )


# ---------------------------------------------------------------------------
# /v1/otel — OpenTelemetry GenAI semantic-convention ingest
# ---------------------------------------------------------------------------


class OtelSpanIn(BaseModel):
    tenant: Optional[str] = None
    agent_id: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    subject_id: Optional[str] = None


_OTEL_MODEL_ATTR = "gen_ai.request.model"
_OTEL_MODEL_VERSION_ATTR = "gen_ai.response.model"
_OTEL_PROMPT_ATTR = "gen_ai.prompt"
_OTEL_COMPLETION_ATTR = "gen_ai.completion"
_OTEL_TOOL_NAME_ATTR = "gen_ai.tool.name"
_OTEL_TOOL_CALL_ID_ATTR = "gen_ai.tool.call.id"
_OTEL_TOOL_ARGS_ATTR = "gen_ai.tool.arguments"
_OTEL_TOOL_RESULT_ATTR = "gen_ai.tool.result"


@app.post("/v1/otel", response_model=list[RecordOut])
def ingest_otel(span: OtelSpanIn, tenant: str = Depends(require_tenant)) -> list[RecordOut]:
    _check_body_tenant(span.tenant, tenant)
    attrs = span.attributes
    model = str(attrs.get(_OTEL_MODEL_ATTR, "unknown"))
    model_version = str(attrs.get(_OTEL_MODEL_VERSION_ATTR, model))
    out: list[RecordOut] = []
    led = get_ledger()
    cap = ledger_mod.max_payload_bytes()

    def _append(kind: str, payload_obj: Any) -> None:
        payload_bytes = (
            payload_obj.encode("utf-8")
            if isinstance(payload_obj, str)
            else json.dumps(payload_obj, default=str).encode("utf-8")
        )
        if len(payload_bytes) > cap:
            raise HTTPException(413, "payload exceeds FLIGHTRECORDER_MAX_PAYLOAD_BYTES")
        _check_plan_limit(tenant)
        result = led.append(
            tenant=tenant,
            agent_id=span.agent_id,
            model=model,
            model_version=model_version,
            kind=kind,
            payload=payload_bytes,
            subject_id=span.subject_id,
        )
        _emit_checkpoint(tenant, result)
        out.append(
            RecordOut(
                seq=result.seq,
                hash=result.hash,
                ts=result.record["ts"],
                dev_mode=result.record["dev_mode"],
            )
        )

    if _OTEL_PROMPT_ATTR in attrs:
        _append("prompt", attrs[_OTEL_PROMPT_ATTR])
    if _OTEL_TOOL_NAME_ATTR in attrs:
        _append(
            "tool_call",
            {
                "tool": attrs.get(_OTEL_TOOL_NAME_ATTR),
                "call_id": attrs.get(_OTEL_TOOL_CALL_ID_ATTR),
                "arguments": attrs.get(_OTEL_TOOL_ARGS_ATTR),
            },
        )
    if _OTEL_TOOL_RESULT_ATTR in attrs:
        _append(
            "tool_result",
            {
                "call_id": attrs.get(_OTEL_TOOL_CALL_ID_ATTR),
                "result": attrs.get(_OTEL_TOOL_RESULT_ATTR),
            },
        )
    if _OTEL_COMPLETION_ATTR in attrs:
        _append("output", attrs[_OTEL_COMPLETION_ATTR])

    if not out:
        raise HTTPException(
            400,
            "no recognized GenAI semantic-convention attributes found "
            f"(expected one of {_OTEL_PROMPT_ATTR}, {_OTEL_COMPLETION_ATTR}, "
            f"{_OTEL_TOOL_NAME_ATTR}, {_OTEL_TOOL_RESULT_ATTR})",
        )
    return out


# ---------------------------------------------------------------------------
# /v1/verify — scoped to the caller's own tenant
# ---------------------------------------------------------------------------


@app.get("/v1/verify")
def verify(tenant: str = Depends(require_tenant)) -> dict[str, Any]:
    records = [r for r in get_ledger().read_all() if r.get("tenant") == tenant]
    result = ledger_mod.verify_records(records, public_key_hex=crypto.public_key_hex())
    return {
        "intact": result.ok,
        "n_records": result.n_records,
        "bad_seq": result.bad_seq,
        "reason": result.reason,
        "dev_mode": crypto.dev_mode(),
    }


# ---------------------------------------------------------------------------
# /v1/export — examiner export, scoped to the caller's own tenant
# ---------------------------------------------------------------------------


@app.get("/v1/export")
def export(
    tenant: str = Depends(require_tenant),
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
    format: str = Query(default="jsonl", pattern="^(jsonl|csv)$"),
) -> StreamingResponse:
    """Regulator pack: records in range + signed checkpoints + tenant public
    key + MAPPING.md (FlightRecorder fields -> EU AI Act Art. 12, ISO/IEC
    42001, FINRA 17a-4(f), SOC 2 CC7). Always a .zip bundle; `format`
    controls whether the record dump inside it is `records.jsonl` or
    `records.csv`."""
    records = [r for r in get_ledger().read_all() if r.get("tenant") == tenant]
    if from_:
        records = [r for r in records if r.get("ts", "") >= from_]
    if to:
        records = [r for r in records if r.get("ts", "") <= to]

    anchors = get_anchor_store().read_all()
    checkpoints = get_witness().read_all(tenant=tenant)
    chain_heads = [{"seq": r["seq"], "hash": r["hash"]} for r in records]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if format == "csv":
            import csv as csv_mod

            csv_buf = io.StringIO()
            fieldnames = [
                "seq",
                "ts",
                "tenant",
                "agent_id",
                "model",
                "model_version",
                "kind",
                "payload_hash",
                "prev_hash",
                "hash",
                "dev_mode",
            ]
            writer = csv_mod.DictWriter(csv_buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in records:
                writer.writerow(r)
            zf.writestr("records.csv", csv_buf.getvalue())
        else:
            zf.writestr(
                "records.jsonl",
                "\n".join(json.dumps(r, sort_keys=True) for r in records)
                + ("\n" if records else ""),
            )
        zf.writestr("chain_heads.json", json.dumps(chain_heads, indent=2))
        zf.writestr(
            "anchors.jsonl",
            "\n".join(json.dumps(a) for a in anchors) + ("\n" if anchors else ""),
        )
        zf.writestr(
            "checkpoints.jsonl",
            "\n".join(json.dumps(c.to_dict(), sort_keys=True) for c in checkpoints)
            + ("\n" if checkpoints else ""),
        )
        zf.writestr("public_key.hex", crypto.public_key_hex())
        zf.writestr("MAPPING.md", mapping_mod.render_mapping_md())
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "tenant": tenant,
                    "from": from_,
                    "to": to,
                    "format": format,
                    "n_records": len(records),
                    "dev_mode": crypto.dev_mode(),
                },
                indent=2,
            ),
        )
    buf.seek(0)
    filename = f"flightrecorder_export_{tenant}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
