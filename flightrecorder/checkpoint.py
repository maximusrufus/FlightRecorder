"""Signed checkpoints against tail-truncation.

A pure hash-chain (even signed) is silent about a DELETED TAIL: if an
attacker with write access to the ledger file truncates the last K lines,
`verify_records` on the truncated file sees a perfectly self-consistent
shorter chain and reports INTACT. Checkpoints close this gap: periodically
(every N records or every T seconds) we emit a signed
`{tenant, seq, head_hash, ts}` checkpoint to a SEPARATE witness location
(not the ledger file itself — the whole point is an attacker who can
truncate the ledger should not automatically also control the witness
store). A verifier with access to at least one honest checkpoint can
detect any truncation at or before that checkpoint's seq.

The witness store here is a local directory (`FLIGHTRECORDER_WITNESS_DIR`),
but `CheckpointWitness` is a small enough interface that swapping it for
S3-with-Object-Lock (write-once) is a drop-in replacement — see the
`write`/`read_all` contract.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import crypto

DEFAULT_EVERY_N = int(os.getenv("FLIGHTRECORDER_CHECKPOINT_EVERY_N", "20"))
DEFAULT_EVERY_SECONDS = float(os.getenv("FLIGHTRECORDER_CHECKPOINT_EVERY_SECONDS", "300"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Checkpoint:
    tenant: str
    seq: int
    head_hash: str
    ts: str
    dev_mode: bool
    sig: str = ""
    tsa_granted: bool = False
    tsa_gen_time: Optional[str] = None
    tsa_token_der_b64: Optional[str] = None

    def signable_bytes(self) -> bytes:
        body = {
            "tenant": self.tenant,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "ts": self.ts,
            "dev_mode": self.dev_mode,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "ts": self.ts,
            "dev_mode": self.dev_mode,
            "sig": self.sig,
            "tsa_granted": self.tsa_granted,
            "tsa_gen_time": self.tsa_gen_time,
            "tsa_token_der_b64": self.tsa_token_der_b64,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Checkpoint":
        return Checkpoint(
            tenant=d["tenant"],
            seq=d["seq"],
            head_hash=d["head_hash"],
            ts=d["ts"],
            dev_mode=d.get("dev_mode", False),
            sig=d.get("sig", ""),
            tsa_granted=d.get("tsa_granted", False),
            tsa_gen_time=d.get("tsa_gen_time"),
            tsa_token_der_b64=d.get("tsa_token_der_b64"),
        )


class CheckpointWitness:
    """Local-file witness store: one JSONL file per tenant, append-only,
    fsync'd. Interface intentionally narrow (`write`, `read_all`) so an
    S3-Object-Lock-backed implementation can be substituted without
    touching callers."""

    def __init__(self, witness_dir: str | Path):
        self.dir = Path(witness_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, tenant: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in tenant)
        return self.dir / f"{safe}.checkpoints.jsonl"

    def write(self, checkpoint: Checkpoint) -> None:
        path = self._path_for(checkpoint.tenant)
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(checkpoint.to_dict(), sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def read_all(self, tenant: Optional[str] = None) -> list[Checkpoint]:
        out: list[Checkpoint] = []
        paths = [self._path_for(tenant)] if tenant else list(self.dir.glob("*.checkpoints.jsonl"))
        for p in paths:
            if not p.exists():
                continue
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(Checkpoint.from_dict(json.loads(line)))
        return out


def sign_checkpoint(checkpoint: Checkpoint) -> Checkpoint:
    checkpoint.sig = crypto.sign(checkpoint.signable_bytes())
    return checkpoint


def verify_checkpoint_sig(checkpoint: Checkpoint, public_key_hex: str) -> bool:
    pub = crypto.load_public_key(public_key_hex)
    return crypto.verify_sig_with_key(checkpoint.signable_bytes(), checkpoint.sig, pub)


class CheckpointScheduler:
    """Decides whether a new checkpoint is due, tracked per tenant."""

    def __init__(
        self,
        every_n: int = DEFAULT_EVERY_N,
        every_seconds: float = DEFAULT_EVERY_SECONDS,
    ):
        self.every_n = every_n
        self.every_seconds = every_seconds
        self._last_seq: dict[str, int] = {}
        self._last_ts: dict[str, float] = {}

    def is_due(self, tenant: str, current_seq: int) -> bool:
        last_seq = self._last_seq.get(tenant, 0)
        last_ts = self._last_ts.get(tenant, 0.0)
        now = time.monotonic()
        if current_seq - last_seq >= self.every_n:
            return True
        if now - last_ts >= self.every_seconds and current_seq > last_seq:
            return True
        return False

    def mark_emitted(self, tenant: str, seq: int) -> None:
        self._last_seq[tenant] = seq
        self._last_ts[tenant] = time.monotonic()


def emit_checkpoint_if_due(
    scheduler: CheckpointScheduler,
    witness: CheckpointWitness,
    *,
    tenant: str,
    head_seq: int,
    head_hash: str,
    attempt_tsa: bool = True,
    tsa_opener=None,
) -> Optional[Checkpoint]:
    if not scheduler.is_due(tenant, head_seq):
        return None
    cp = Checkpoint(
        tenant=tenant,
        seq=head_seq,
        head_hash=head_hash,
        ts=_now_iso(),
        dev_mode=crypto.dev_mode(),
    )
    sign_checkpoint(cp)

    if attempt_tsa:
        import base64

        from . import anchor, rfc3161_min

        result = rfc3161_min.request_timestamp(
            bytes.fromhex(head_hash), anchor.DEFAULT_TSA_URL, opener=tsa_opener
        )
        cp.tsa_granted = bool(result.get("granted"))
        cp.tsa_gen_time = result.get("gen_time")
        raw_token = result.get("raw_token")
        if raw_token:
            cp.tsa_token_der_b64 = base64.b64encode(raw_token).decode("ascii")

    witness.write(cp)
    scheduler.mark_emitted(tenant, head_seq)
    return cp
