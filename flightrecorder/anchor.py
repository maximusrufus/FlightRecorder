"""Periodic anchoring of ledger chain heads.

Adapted from an internal Merkle anchoring module: the Merkle-tree
folding logic is a direct, trimmed port (OpenTimestamps/Bitcoin path
dropped — not needed for a broker-dealer examiner audit trail); the
RFC 3161 TSA client is `rfc3161_min.py` (vendored separately, see that
file's docstring).

Design: rather than anchoring every record, we anchor the *chain head*
(the `hash` of the latest ledger record) periodically. An RFC 3161
timestamp token over that head proves the entire chain up to that record
existed by the TSA's stated time — cheap (one anchor covers arbitrarily
many records) and matches how 17a-4(f)-style WORM audit trails are usually
notarized in practice.

The TSA URL is configurable (`FLIGHTRECORDER_TSA_URL`, default
`https://freetsa.org/tsr`) and no test in this repo makes a live network
call — `request_timestamp`'s `opener` parameter is always injected with a
fake in tests.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from . import rfc3161_min

DEFAULT_TSA_URL = os.getenv("FLIGHTRECORDER_TSA_URL", "https://freetsa.org/tsr")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(hash_hex: str) -> bytes:
    return _sha256(b"\x00" + bytes.fromhex(hash_hex))


def _node(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return "0" * 64
    level = [_leaf(h) for h in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_node(left, right))
        level = nxt
    return level[0].hex()


def merkle_proof(hashes: list[str], index: int) -> list[dict[str, str]]:
    if index < 0 or index >= len(hashes):
        raise IndexError("index out of range for merkle_proof")
    level = [_leaf(h) for h in hashes]
    idx = index
    proof: list[dict[str, str]] = []
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            if i == idx or i + 1 == idx:
                if idx % 2 == 0:
                    proof.append({"side": "right", "hash": right.hex()})
                else:
                    proof.append({"side": "left", "hash": left.hex()})
            nxt.append(_node(left, right))
        idx //= 2
        level = nxt
    return proof


def verify_merkle_proof(
    leaf_hex: str, proof: list[dict[str, str]], root_hex: str
) -> bool:
    try:
        acc = _leaf(leaf_hex)
        for step in proof:
            sib = bytes.fromhex(step["hash"])
            if step["side"] == "left":
                acc = _node(sib, acc)
            elif step["side"] == "right":
                acc = _node(acc, sib)
            else:
                return False
        return acc.hex() == root_hex.lower()
    except (ValueError, KeyError, TypeError):
        return False


@dataclass
class AnchorRecord:
    anchored_at: str
    chain_head_hash: str
    merkle_root: str
    tsa_url: Optional[str]
    tsa_granted: bool
    tsa_gen_time: Optional[str]
    tsa_token_der_b64: Optional[str]
    tsa_reason: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchored_at": self.anchored_at,
            "chain_head_hash": self.chain_head_hash,
            "merkle_root": self.merkle_root,
            "tsa_url": self.tsa_url,
            "tsa_granted": self.tsa_granted,
            "tsa_gen_time": self.tsa_gen_time,
            "tsa_token_der_b64": self.tsa_token_der_b64,
            "tsa_reason": self.tsa_reason,
        }


class AnchorStore:
    """Append-only JSONL store of anchor records (separate file from the
    ledger — anchors are metadata about the chain, not chain entries)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, rec: AnchorRecord) -> None:
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec.to_dict(), separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def read_all(self) -> list[dict[str, Any]]:
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


def anchor_chain_head(
    record_hashes: list[str],
    store: AnchorStore,
    *,
    tsa_url: str = DEFAULT_TSA_URL,
    opener: Optional[Callable] = None,
    attempt_tsa: bool = True,
) -> AnchorRecord:
    """Fold `record_hashes` (all record `hash` values seen so far, in order)
    into a Merkle root, best-effort RFC-3161-timestamp that root, and
    persist an anchor record. Never raises — TSA failure just yields
    `tsa_granted=False` with a reason; the Merkle root itself is always
    computed and stored (offline-verifiable, no network needed).

    `opener` is passed straight through to `rfc3161_min.request_timestamp`
    so tests never touch the network.
    """
    root = merkle_root(record_hashes)
    head_hash = record_hashes[-1] if record_hashes else "0" * 64

    granted = False
    gen_time = None
    token_b64 = None
    reason = None

    if attempt_tsa:
        result = rfc3161_min.request_timestamp(
            bytes.fromhex(root), tsa_url, opener=opener
        )
        granted = bool(result.get("granted"))
        gen_time = result.get("gen_time")
        reason = result.get("reason")
        raw_token = result.get("raw_token")
        if raw_token:
            import base64

            token_b64 = base64.b64encode(raw_token).decode("ascii")
    else:
        reason = "tsa_not_attempted"

    rec = AnchorRecord(
        anchored_at=datetime.now(timezone.utc).isoformat(),
        chain_head_hash=head_hash,
        merkle_root=root,
        tsa_url=tsa_url if attempt_tsa else None,
        tsa_granted=granted,
        tsa_gen_time=gen_time,
        tsa_token_der_b64=token_b64,
        tsa_reason=reason,
    )
    store.append(rec)
    return rec
