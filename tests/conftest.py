import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set BEFORE any flightrecorder import: flightrecorder.proxy performs an eager
# key-material check at MODULE IMPORT time (fail-fast on startup), so this
# must be in place before pytest's collection imports it anywhere in the
# suite. The startup-refusal behavior itself is tested in a subprocess
# (test_startup_refusal.py) with this variable explicitly removed.
os.environ.setdefault("FLIGHTRECORDER_DEV", "1")

import pytest

from flightrecorder import crypto


@pytest.fixture(autouse=True)
def _dev_mode_ephemeral_keys(monkeypatch):
    """Every test runs with FLIGHTRECORDER_DEV=1 (fresh random ephemeral keys,
    cleared per test) unless a test explicitly overrides FLIGHTRECORDER_KEK /
    FLIGHTRECORDER_SIGNING_KEY and unsets FLIGHTRECORDER_DEV itself. This keeps
    the test suite from ever depending on a hardcoded/shared key, mirroring
    production's "no fallback" posture."""
    monkeypatch.setenv("FLIGHTRECORDER_DEV", "1")
    crypto._kek.cache_clear()
    crypto._signing_seed.cache_clear()
    crypto._private_key.cache_clear()
    crypto._public_key.cache_clear()
    yield
    crypto._kek.cache_clear()
    crypto._signing_seed.cache_clear()
    crypto._private_key.cache_clear()
    crypto._public_key.cache_clear()


@pytest.fixture()
def tmp_ledger_path(tmp_path):
    return tmp_path / "ledger.jsonl"


import base64  # noqa: E402


@pytest.fixture()
def real_keys_env(monkeypatch):
    """Opt a test OUT of the default dev-ephemeral-random-key posture and
    into fixed, explicit (test-only) key material -- for tests that need a
    STABLE key across multiple ledger/proxy instances within the same test
    (e.g. tamper-detection exit-code checks, which would otherwise be
    masked by the dev-mode exit-3 override) or across multiple OS
    PROCESSES (the concurrent-append test: dev mode's per-process random
    key would give each subprocess a DIFFERENT signing key)."""
    monkeypatch.delenv("FLIGHTRECORDER_DEV", raising=False)
    monkeypatch.setenv("FLIGHTRECORDER_KEK", base64.b64encode(b"\x11" * 32).decode())
    monkeypatch.setenv(
        "FLIGHTRECORDER_SIGNING_KEY", base64.b64encode(b"\x22" * 32).decode()
    )
    crypto._kek.cache_clear()
    crypto._signing_seed.cache_clear()
    crypto._private_key.cache_clear()
    crypto._public_key.cache_clear()
    yield
    crypto._kek.cache_clear()
    crypto._signing_seed.cache_clear()
    crypto._private_key.cache_clear()
    crypto._public_key.cache_clear()
