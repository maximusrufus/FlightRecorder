"""Offline, standalone verifier an examiner runs against an export zip.

Usage:
    python -m flightrecorder.verify_cli export.zip --trusted-key <hex>
    python -m flightrecorder.verify_cli export.zip --trusted-fingerprint <sha256-hex>
    python -m flightrecorder.verify_cli export.zip --trusted-key <hex> --expected-head 42:abcd...

Exit codes:
    0 — chain intact, key trusted, no dev-mode taint
    1 — usage error (missing --trusted-key/--trusted-fingerprint, bad zip, ...)
    2 — tampered / untrusted key / checkpoint or expected-head mismatch
    3 — export was produced in FLIGHTRECORDER_DEV=1 mode — NOT a real audit
        trail regardless of whether the chain itself verifies

SECURITY: this tool trusts NOTHING it reads out of the export zip itself
for identity purposes. The bundled `public_key.hex` is only ever used
after being matched against an out-of-band `--trusted-key` /
`--trusted-fingerprint` the examiner supplies from a separate channel (the
broker-dealer's own records of the key it was given, a signed onboarding
doc, etc). Without one of those two flags this tool refuses to verify
anything (exit 1) — verifying against a self-declared key is not a
security check.

Depends only on stdlib + `cryptography` (Ed25519 + fingerprint hashing) —
no FastAPI, no network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from typing import Any, Optional

from . import checkpoint as checkpoint_mod
from . import crypto
from .ledger import verify_records


class ExportReadError(RuntimeError):
    pass


class UsageError(RuntimeError):
    pass


def _load_export(zip_path: str) -> dict[str, Any]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        if "records.jsonl" not in names:
            raise ExportReadError("export zip missing records.jsonl")
        if "public_key.hex" not in names:
            raise ExportReadError("export zip missing public_key.hex")
        records_raw = zf.read("records.jsonl").decode("utf-8")
        pub_hex = zf.read("public_key.hex").decode("utf-8").strip()
        checkpoints_raw = (
            zf.read("checkpoints.jsonl").decode("utf-8")
            if "checkpoints.jsonl" in names
            else ""
        )
        transitions_raw = (
            zf.read("key_transitions.jsonl").decode("utf-8")
            if "key_transitions.jsonl" in names
            else ""
        )
        manifest = (
            json.loads(zf.read("manifest.json").decode("utf-8"))
            if "manifest.json" in names
            else {}
        )

    records = [json.loads(line) for line in records_raw.splitlines() if line.strip()]
    checkpoints = [
        checkpoint_mod.Checkpoint.from_dict(json.loads(line))
        for line in checkpoints_raw.splitlines()
        if line.strip()
    ]
    transitions = [
        json.loads(line) for line in transitions_raw.splitlines() if line.strip()
    ]
    return {
        "records": records,
        "pub_hex": pub_hex,
        "checkpoints": checkpoints,
        "transitions": transitions,
        "manifest": manifest,
    }


def _fingerprint(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


def _establish_trust(
    bundled_pub_hex: str,
    transitions: list[dict[str, Any]],
    *,
    trusted_key: Optional[str],
    trusted_fingerprint: Optional[str],
) -> tuple[bool, str]:
    """Returns (trusted, message). A key-rotation transition record is
    {old_key_hex, new_key_hex, sig} where `sig` is old_key's Ed25519
    signature over new_key_hex.encode(). Trust is established if
    bundled_pub_hex == trusted_key/fingerprint directly, OR is reachable
    from the trusted key by walking a chain of validly-signed
    transitions."""
    if trusted_key and bundled_pub_hex == trusted_key:
        return True, "bundled key matches --trusted-key directly"
    if trusted_fingerprint and _fingerprint(bundled_pub_hex) == trusted_fingerprint:
        return True, "bundled key matches --trusted-fingerprint directly"

    # Attempt rotation-chain reachability starting from the trusted key.
    start_key = trusted_key
    if start_key is None and trusted_fingerprint is not None:
        # Fingerprint alone can't seed a chain walk (we don't have the hex);
        # only direct-match is supported for fingerprint-only trust.
        return (
            False,
            "untrusted key: no rotation path checkable from a fingerprint alone",
        )

    if start_key is None:
        return False, "untrusted key: bundled key does not match trusted key"

    frontier = {start_key}
    changed = True
    while changed:
        changed = False
        if bundled_pub_hex in frontier:
            return True, "bundled key reachable via signed key-transition chain"
        for t in transitions:
            old_key, new_key, sig = (
                t.get("old_key_hex"),
                t.get("new_key_hex"),
                t.get("sig"),
            )
            if not (old_key and new_key and sig):
                continue
            if old_key in frontier and new_key not in frontier:
                try:
                    pub = crypto.load_public_key(old_key)
                except (ValueError, TypeError):
                    continue
                if crypto.verify_sig_with_key(new_key.encode("utf-8"), sig, pub):
                    frontier.add(new_key)
                    changed = True

    if bundled_pub_hex in frontier:
        return True, "bundled key reachable via signed key-transition chain"
    return (
        False,
        "untrusted key: not the trusted key and not reachable via any valid rotation chain",
    )


def _verify_checkpoints(
    records: list[dict[str, Any]],
    checkpoints: list[checkpoint_mod.Checkpoint],
    pub_hex: str,
) -> tuple[bool, str, int]:
    """Returns (ok, message, unanchored_tail_count)."""
    if not records:
        return True, "no records to checkpoint", 0
    by_seq = {r["seq"]: r for r in records}
    max_seq = max(by_seq)

    last_checkpoint_seq = 0
    for cp in checkpoints:
        if not checkpoint_mod.verify_checkpoint_sig(cp, pub_hex):
            return False, f"checkpoint at seq={cp.seq} has an invalid signature", 0
        if cp.seq > max_seq:
            return (
                False,
                f"checkpoint claims seq={cp.seq} but export's max record seq is {max_seq} (tail truncated after export?)",
                0,
            )
        record_at_seq = by_seq.get(cp.seq)
        if record_at_seq is None or record_at_seq["hash"] != cp.head_hash:
            return (
                False,
                f"checkpoint at seq={cp.seq} head_hash does not match the record at that seq (tail truncation / rewrite)",
                0,
            )
        last_checkpoint_seq = max(last_checkpoint_seq, cp.seq)

    unanchored_tail = max_seq - last_checkpoint_seq
    return True, "checkpoints consistent", unanchored_tail


def verify_export(
    zip_path: str,
    *,
    trusted_key: Optional[str] = None,
    trusted_fingerprint: Optional[str] = None,
    expected_head: Optional[tuple[int, str]] = None,
) -> tuple[bool, str]:
    """Returns (ok, message). Raises ExportReadError / UsageError for
    usage/file-level problems, distinct from a tamper/trust finding."""
    if not trusted_key and not trusted_fingerprint:
        raise UsageError(
            "no --trusted-key or --trusted-fingerprint given -- refusing to "
            "verify against a self-declared key from inside the export"
        )

    try:
        bundle = _load_export(zip_path)
    except (ValueError, KeyError, zipfile.BadZipFile, OSError) as exc:
        raise ExportReadError(str(exc)) from exc

    records = bundle["records"]
    pub_hex = bundle["pub_hex"]

    trusted, trust_msg = _establish_trust(
        pub_hex,
        bundle["transitions"],
        trusted_key=trusted_key,
        trusted_fingerprint=trusted_fingerprint,
    )
    if not trusted:
        return False, trust_msg

    result = verify_records(records, public_key_hex=pub_hex)
    if not result.ok:
        return False, f"TAMPERED — first bad seq={result.bad_seq}: {result.reason}"

    cp_ok, cp_msg, unanchored_tail = _verify_checkpoints(
        records, bundle["checkpoints"], pub_hex
    )
    if not cp_ok:
        return False, f"TAMPERED — {cp_msg}"

    if expected_head is not None:
        exp_seq, exp_hash = expected_head
        by_seq = {r["seq"]: r for r in records}
        rec = by_seq.get(exp_seq)
        if rec is None or rec["hash"] != exp_hash:
            return (
                False,
                f"TAMPERED — --expected-head {exp_seq}:{exp_hash} does not match export",
            )

    msg = f"INTACT — {result.n_records} records verified, chain unbroken, key trusted ({trust_msg})"
    if unanchored_tail:
        msg += f"; WARNING: {unanchored_tail} record(s) after the last checkpoint are not yet anchored"
    return True, msg


def _parse_expected_head(raw: str) -> tuple[int, str]:
    try:
        seq_str, hash_hex = raw.split(":", 1)
        return int(seq_str), hash_hex
    except ValueError as exc:
        raise UsageError(f"--expected-head must be seq:hash, got {raw!r}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FlightRecorder offline export verifier")
    parser.add_argument("export_zip", help="path to an FlightRecorder export .zip")
    parser.add_argument(
        "--trusted-key",
        help="the Ed25519 public key (hex) you trust, from an out-of-band source",
    )
    parser.add_argument(
        "--trusted-fingerprint", help="sha256 hex fingerprint of the trusted public key"
    )
    parser.add_argument(
        "--expected-head", help="seq:hash pair from an external source to cross-check"
    )
    args = parser.parse_args(argv)

    try:
        expected_head = (
            _parse_expected_head(args.expected_head) if args.expected_head else None
        )
        ok, message = verify_export(
            args.export_zip,
            trusted_key=args.trusted_key,
            trusted_fingerprint=args.trusted_fingerprint,
            expected_head=expected_head,
        )
    except (ExportReadError, UsageError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Dev-mode taint check: an export produced under FLIGHTRECORDER_DEV=1 is
    # never a real audit trail, no matter how cleanly it verifies.
    try:
        bundle = _load_export(args.export_zip)
        dev_tainted = bool(bundle["manifest"].get("dev_mode")) or any(
            r.get("dev_mode") for r in bundle["records"]
        )
    except Exception:
        dev_tainted = False

    if dev_tainted:
        print(
            "*** DEV MODE EXPORT — NOT A VALID AUDIT TRAIL (FLIGHTRECORDER_DEV=1 was used) ***",
            file=sys.stderr,
        )
        print(message)
        return 3

    print(message)
    if not ok:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
