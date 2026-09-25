"""Fails if any tracked file contains what looks like a live/test Stripe
secret (sk_live_, rk_live_, sk_test_, rk_test_) or webhook signing secret
(whsec_). Run in CI / pre-commit; never touches the network."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERN = re.compile(r"(sk|rk)_(live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,}")

# Files that legitimately mention the *shape* of a key without being one
# (this script's own docstring/pattern, fixtures using obviously-fake
# short placeholders) are still scanned -- the length gate above already
# keeps short placeholders like "sk_test_x" from tripping false positives
# only if they're under 8 chars after the prefix; real keys are 24+.
EXCLUDE_DIRS = {".git", ".venv", "node_modules", "__pycache__"}


def tracked_files(repo_root: Path) -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [repo_root / line for line in out.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback for environments without git: walk the tree.
        return [
            p
            for p in repo_root.rglob("*")
            if p.is_file() and not any(part in EXCLUDE_DIRS for part in p.parts)
        ]


def scan(repo_root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in tracked_files(repo_root):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name == "check_no_stripe_keys.py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = PATTERN.search(line)
            if match:
                findings.append((path, lineno, match.group(0)[:12] + "..."))
    return findings


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    findings = scan(repo_root)
    if findings:
        print("Found possible committed Stripe secrets:", file=sys.stderr)
        for path, lineno, snippet in findings:
            print(f"  {path}:{lineno}: {snippet}", file=sys.stderr)
        return 1
    print("No Stripe secrets found in tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
