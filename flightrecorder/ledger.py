"""Append-only, tamper-evident JSONL ledger for AI-agent activity records.

Adapted from an internal hash-chained receipt ledger
design (hash-chained, one fsync'd line per record, never rewritten) and
an internal hash-chain store (hash-over-stored-body so crypto-shred
keeps the chain verifiable after a subject key is destroyed).

Record shape (one JSON object per line):
    {
      "seq": int,                # 1-based, gap-free, monotonic
      "ts": iso8601 str,
      "tenant": str,
      "agent_id": str,
      "model": str,
      "model_version": str,
      "kind": "prompt"|"output"|"tool_call"|"tool_result",
      "payload_hash": hex sha256 of the CIPHERTEXT (payload_enc),
      "payload_enc": base64 str (Fernet ciphertext; opaque after shred),
      "prev_hash": hex sha256 of the previous record (GENESIS for seq=1),
      "hash": hex sha256 over the canonical record (all fields above,
              sorted, excluding "hash" and "sig"),
      "sig": hex Ed25519 signature over bytes.fromhex(hash)
    }

Locking: a cross-process `FileLock` (see `filelock.py`) serializes the
read-last-line -> compute-next -> append -> fsync critical section, so N
concurrent OS processes appending to the same ledger file produce a
gap-free, correctly-chained sequence with no torn writes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from . import crypto, durable
from .filelock import FileLock

GENESIS = "0" * 64

VALID_KINDS = ("prompt", "output", "tool_call", "tool_result", "shred")

DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB


def max_payload_bytes() -> int:
    return int(os.getenv("FLIGHTRECORDER_MAX_PAYLOAD_BYTES", str(DEFAULT_MAX_PAYLOAD_BYTES)))


# Fields covered by the record hash, in a fixed order (order doesn't affect
# the digest since json.dumps(sort_keys=True) is used, but it documents the
# exact field set a reimplementation must match).
_HASHED_FIELDS = (
    "seq",
    "ts",
    "tenant",
    "agent_id",
    "model",
    "model_version",
    "kind",
    "payload_hash",
    "payload_enc",
    "prev_hash",
    "subject_id",
    "dev_mode",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def record_hash(record: dict[str, Any]) -> str:
    body = {k: record.get(k) for k in _HASHED_FIELDS}
    return _sha256_hex(_canonical(body))


@dataclass
class AppendResult:
    seq: int
    hash: str
    record: dict[str, Any]


class LedgerError(RuntimeError):
    pass


class Ledger:
    """One ledger = one append-only JSONL file + its keystore."""

    def __init__(self, path: str | Path, keystore: Optional[crypto.Keystore] = None):
        self.path = Path(path)
        if durable.is_active():
            durable.restore_once(str(self.path.parent))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self.keystore = keystore or crypto.Keystore(self.path.with_suffix(".keys.json"))

    # -- internal: read the last line without loading the whole file -------
    def _last_record(self) -> Optional[dict[str, Any]]:
        last_line = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return None
        return json.loads(last_line)

    def append(
        self,
        *,
        tenant: str,
        agent_id: str,
        model: str,
        model_version: str,
        kind: str,
        payload: bytes,
        subject_id: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> AppendResult:
        if kind not in VALID_KINDS:
            raise LedgerError(f"invalid kind {kind!r}; must be one of {VALID_KINDS}")

        cap = max_payload_bytes()
        if len(payload) > cap:
            raise LedgerError(
                f"payload of {len(payload)} bytes exceeds FLIGHTRECORDER_MAX_PAYLOAD_BYTES={cap}"
            )

        subject = subject_id or f"{tenant}:{agent_id}"
        payload_enc = crypto.encrypt_payload(self.keystore, subject, payload)
        payload_enc_b64 = base64.b64encode(payload_enc).decode("ascii")
        # Hash is computed over the CIPHERTEXT (crypto-shred property): once
        # the subject key is destroyed, payload_enc is opaque garbage but
        # payload_hash / the chain still verify exactly as before.
        payload_hash = _sha256_hex(payload_enc)

        with FileLock(self.path):
            prev = self._last_record()
            prev_hash = prev["hash"] if prev else GENESIS
            seq = (prev["seq"] + 1) if prev else 1

            record: dict[str, Any] = {
                "seq": seq,
                "ts": ts or _now_iso(),
                "tenant": tenant,
                "agent_id": agent_id,
                "model": model,
                "model_version": model_version,
                "kind": kind,
                "payload_hash": payload_hash,
                "payload_enc": payload_enc_b64,
                "prev_hash": prev_hash,
                "subject_id": subject,
                "dev_mode": crypto.dev_mode(),
            }
            h = record_hash(record)
            record["hash"] = h
            record["sig"] = crypto.sign(bytes.fromhex(h))

            line = _canonical(record)
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            if durable.is_active():
                durable.persist(str(self.path.parent))

        return AppendResult(seq=seq, hash=h, record=record)

    def read_all(self) -> Iterator[dict[str, Any]]:
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def decrypt_record_payload(self, record: dict[str, Any]) -> Optional[bytes]:
        subject = record.get("subject_id") or f"{record['tenant']}:{record['agent_id']}"
        ciphertext = base64.b64decode(record["payload_enc"])
        return crypto.decrypt_payload(self.keystore, subject, ciphertext)

    def shred_subject(self, subject_id: str, *, tenant: str, agent_id: str) -> bool:
        """Destroy a subject's data key and append a `shred` record to the
        chain documenting the event (the subject id's HASH, never the key
        material or plaintext). Returns True iff a key existed to shred."""
        existed = self.keystore.shred(subject_id)
        shred_payload = json.dumps(
            {"shredded_subject_hash": _sha256_hex(subject_id), "existed": existed}
        ).encode("utf-8")
        # The shred record itself is stored under a system subject that is
        # never shredded, so the ledger's own encryption invariant holds
        # uniformly even for records ABOUT a shred.
        self.append(
            tenant=tenant,
            agent_id=agent_id,
            model="system",
            model_version="system",
            kind="shred",
            payload=shred_payload,
            subject_id=f"_system:{tenant}",
        )
        return existed

    def head(self) -> Optional[dict[str, str]]:
        """Current chain head: {seq, hash} or None if the ledger is empty."""
        last = self._last_record()
        if last is None:
            return None
        return {"seq": last["seq"], "hash": last["hash"]}


# ---------------------------------------------------------------------------
# Standalone verification (used by both the API's /v1/verify and the
# offline verify_cli.py — kept dependency-free of the Ledger class itself
# so verify_cli can run against an export with only stdlib + cryptography).
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool
    n_records: int
    bad_seq: Optional[int] = None
    reason: Optional[str] = None


def verify_records(
    records: list[dict[str, Any]],
    public_key_hex: Optional[str] = None,
) -> VerifyResult:
    """Verify hash chain linkage (+ signature, if a public key is supplied)
    over an ordered list of records. Never raises.

    Detects: byte-level tampering (hash/sig mismatch at the tampered seq),
    deleted lines (a gap in `seq` or a broken prev_hash linkage), and
    reordering (prev_hash chain no longer matches traversal order).
    """
    if not records:
        return VerifyResult(ok=True, n_records=0)

    pub = crypto.load_public_key(public_key_hex) if public_key_hex else None
    prev_hash = GENESIS
    expected_seq = None

    for rec in records:
        seq = rec.get("seq")
        if expected_seq is not None and seq != expected_seq:
            return VerifyResult(
                ok=False,
                n_records=len(records),
                bad_seq=expected_seq,
                reason=f"missing or out-of-order seq: expected {expected_seq}, got {seq}",
            )
        expected_seq = (seq if isinstance(seq, int) else 0) + 1

        if rec.get("prev_hash") != prev_hash:
            return VerifyResult(
                ok=False,
                n_records=len(records),
                bad_seq=seq,
                reason=f"prev_hash mismatch at seq={seq}",
            )

        recomputed = record_hash(rec)
        if recomputed != rec.get("hash"):
            return VerifyResult(
                ok=False,
                n_records=len(records),
                bad_seq=seq,
                reason=f"hash mismatch at seq={seq} (payload or metadata tampered)",
            )

        sig = rec.get("sig")
        if pub is not None:
            if not sig or not crypto.verify_sig_with_key(bytes.fromhex(recomputed), sig, pub):
                return VerifyResult(
                    ok=False,
                    n_records=len(records),
                    bad_seq=seq,
                    reason=f"signature invalid at seq={seq}",
                )

        prev_hash = rec["hash"]

    return VerifyResult(ok=True, n_records=len(records))
