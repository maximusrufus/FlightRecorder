"""`flightrecorder` command-line entry point.

    flightrecorder verify <ledger-path-or-export.zip-or-url>

Exit codes: 0 = chain intact, 1 = usage error, 2 = chain tampered,
3 = dev-mode export (never a valid audit trail).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import ledger as ledger_mod
from . import verify_cli as export_verify


def _verify_local_ledger(path: Path, trusted_key: str | None = None) -> int:
    """Verify hash-chain linkage of a raw .jsonl ledger file. Signature
    verification is opt-in via --trusted-key: a bare ledger file carries no
    public key of its own (that's what the .zip export bundle is for), and
    a per-process dev-mode key would never match the writer's key anyway."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    result = ledger_mod.verify_records(records, public_key_hex=trusted_key)
    if result.ok:
        print(f"OK: chain intact ({result.n_records} records)")
        return 0
    print(f"TAMPERED: {result.reason} (at seq={result.bad_seq})", file=sys.stderr)
    return 2


def _verify_url(url: str) -> int:
    req = urllib.request.Request(url.rstrip("/") + "/v1/verify")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"ERROR: could not reach {url}: {exc}", file=sys.stderr)
        return 1
    if data.get("intact"):
        print(f"OK: chain intact ({data.get('n_records')} records)")
        return 0
    print(f"TAMPERED: {data.get('reason')} (at seq={data.get('bad_seq')})", file=sys.stderr)
    return 2


def cmd_verify(args: argparse.Namespace) -> int:
    target = args.target
    if target.startswith("http://") or target.startswith("https://"):
        return _verify_url(target)

    path = Path(target)
    if not path.exists():
        print(f"ERROR: no such file: {target}", file=sys.stderr)
        return 1

    if path.suffix == ".zip":
        return export_verify.main(
            [str(path)]
            + (["--trusted-key", args.trusted_key] if args.trusted_key else [])
            + (
                ["--trusted-fingerprint", args.trusted_fingerprint]
                if args.trusted_fingerprint
                else []
            )
        )

    return _verify_local_ledger(path, trusted_key=args.trusted_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="flightrecorder")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify a ledger's hash chain")
    p_verify.add_argument("target", help="path to a .jsonl ledger, an export .zip, or a base URL")
    p_verify.add_argument("--trusted-key", default=None)
    p_verify.add_argument("--trusted-fingerprint", default=None)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
