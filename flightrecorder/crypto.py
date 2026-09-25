"""Signing (Ed25519) + per-subject data keys for crypto-shred.

SECURITY-CRITICAL key-management rules (2026-09-13 hardening pass, after an
adversarial review found the original design was theater):

  - There is NO hardcoded/derivable dev-key fallback. `FLIGHTRECORDER_SIGNING_KEY`
    and `FLIGHTRECORDER_KEK` are REQUIRED. If either is missing, the process
    refuses to start (`KeyConfigError`) UNLESS `FLIGHTRECORDER_DEV=1`, in which
    case fresh RANDOM ephemeral keys are generated per process (never
    persisted, never reused across restarts) and every record/export is
    stamped `dev_mode: true` so a dev export can never be mistaken for a
    real audit trail.
  - Per-subject data keys are RANDOM (`os.urandom(32)`), never derived from
    the KEK or signing key by any deterministic function. They are wrapped
    (Fernet-encrypted) by the KEK for storage. This means an attacker who
    recovers the KEK cannot "re-derive" a shredded subject's key — the only
    copy of the real key existed in the (now-deleted) wrapped keystore
    entry. This closes the HKDF-rederivation attack the earlier
    HKDF-from-master-key design was vulnerable to.
  - Shredding is an atomic rewrite (temp file + fsync + os.replace) of the
    keystore, guarded by the SAME cross-process FileLock used for writes.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from flightrecorder.filelock import FileLock


class KeyConfigError(RuntimeError):
    """Raised when required key material is missing and FLIGHTRECORDER_DEV!=1."""


def dev_mode() -> bool:
    return os.getenv("FLIGHTRECORDER_DEV") == "1"


def _b64_32(raw_b64: str, var_name: str) -> bytes:
    key = base64.b64decode(raw_b64)
    if len(key) != 32:
        raise KeyConfigError(f"{var_name} must decode to exactly 32 raw bytes")
    return key


@lru_cache(maxsize=1)
def _kek() -> bytes:
    """Key-encryption-key: wraps per-subject data keys for storage."""
    raw = os.getenv("FLIGHTRECORDER_KEK")
    if raw:
        return _b64_32(raw, "FLIGHTRECORDER_KEK")
    if dev_mode():
        return os.urandom(32)
    raise KeyConfigError(
        "FLIGHTRECORDER_KEK is not set. FlightRecorder refuses to start without an "
        "explicit key-encryption-key (production requires real key material; "
        "there is no dev fallback). Set FLIGHTRECORDER_DEV=1 to run with "
        "throwaway random keys for local development/testing only — every "
        "record and export will then be stamped dev_mode=true."
    )


@lru_cache(maxsize=1)
def _signing_seed() -> bytes:
    raw = os.getenv("FLIGHTRECORDER_SIGNING_KEY")
    if raw:
        return _b64_32(raw, "FLIGHTRECORDER_SIGNING_KEY")
    if dev_mode():
        return os.urandom(32)
    raise KeyConfigError(
        "FLIGHTRECORDER_SIGNING_KEY is not set. FlightRecorder refuses to start "
        "without an explicit Ed25519 signing seed (production requires real "
        "key material; there is no dev fallback). Set FLIGHTRECORDER_DEV=1 to "
        "run with a throwaway random signing key for local "
        "development/testing only — every record and export will then be "
        "stamped dev_mode=true."
    )


@lru_cache(maxsize=1)
def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_signing_seed())


@lru_cache(maxsize=1)
def _public_key() -> Ed25519PublicKey:
    return _private_key().public_key()


def sign(data: bytes) -> str:
    """Sign `data` (already-hashed record bytes) -> hex-encoded signature."""
    return _private_key().sign(data).hex()


def verify_sig(data: bytes, sig_hex: str) -> bool:
    try:
        signature = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    try:
        _public_key().verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_hex() -> str:
    return _public_key().public_bytes_raw().hex()


def load_public_key(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def verify_sig_with_key(data: bytes, sig_hex: str, pub: Ed25519PublicKey) -> bool:
    try:
        signature = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    try:
        pub.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Per-subject data keys (crypto-shred) — RANDOM keys, KEK-wrapped at rest
# ---------------------------------------------------------------------------

_keystore_lock = threading.Lock()


def _kek_fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_kek()))


class Keystore:
    """File-backed JSON keystore: subject_id -> base64(Fernet(KEK).encrypt(raw_32_byte_key)).

    The stored value is the RANDOM data key, wrapped for at-rest storage —
    never a value re-derivable from the KEK alone. Deleting a subject's
    entry ("shredding") destroys the only copy of that key; the KEK cannot
    reconstruct it. The ledger's hash chain is computed over the ciphertext
    produced by that key, so verification is unaffected by shredding.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}", encoding="utf-8")

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(self.path.suffix + f".tmp.{os.getpid()}")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(data))
            f.flush()
            os.fsync(f.fileno())
        # os.replace() is protected by our own cross-process FileLock at the
        # call site, but on Windows a concurrent short-lived reader handle
        # (our own _read(), AV/indexer) can still cause a transient
        # ERROR_ACCESS_DENIED even though no other WRITER is racing us.
        # Bounded retry, not a correctness weakening -- the lock already
        # guarantees only one writer.
        last_exc: Optional[OSError] = None
        for _ in range(50):
            try:
                os.replace(tmp, self.path)
                return
            except PermissionError as exc:
                last_exc = exc
                time.sleep(0.02)
        raise last_exc  # pragma: no cover - only on persistent OS-level lock

    def get_or_create_key(self, subject_id: str) -> bytes:
        with _keystore_lock:
            data = self._read()
            wrapped_b64 = data.get(subject_id)
            if wrapped_b64 is not None:
                return _kek_fernet().decrypt(base64.b64decode(wrapped_b64))
            with FileLock(self.path):
                data = self._read()
                wrapped_b64 = data.get(subject_id)
                if wrapped_b64 is None:
                    raw_key = os.urandom(32)  # RANDOM, never derived
                    wrapped = _kek_fernet().encrypt(raw_key)
                    data[subject_id] = base64.b64encode(wrapped).decode("ascii")
                    self._write(data)
                    return raw_key
            return _kek_fernet().decrypt(base64.b64decode(wrapped_b64))

    def get_key(self, subject_id: str) -> Optional[bytes]:
        with _keystore_lock:
            data = self._read()
            wrapped_b64 = data.get(subject_id)
            if wrapped_b64 is None:
                return None
            try:
                return _kek_fernet().decrypt(base64.b64decode(wrapped_b64))
            except InvalidToken:
                return None

    def shred(self, subject_id: str) -> bool:
        """Irrecoverably delete a subject's data key. Returns True if a key
        existed and was removed. Atomic (temp file + fsync + os.replace)."""
        with _keystore_lock, FileLock(self.path):
            data = self._read()
            if subject_id in data:
                del data[subject_id]
                self._write(data)
                return True
            return False

    def is_shredded(self, subject_id: str) -> bool:
        with _keystore_lock:
            return subject_id not in self._read()


def encrypt_payload(keystore: Keystore, subject_id: str, plaintext: bytes) -> bytes:
    key = keystore.get_or_create_key(subject_id)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.encrypt(plaintext)


def decrypt_payload(
    keystore: Keystore, subject_id: str, ciphertext: bytes
) -> Optional[bytes]:
    """Returns None (never raises) if the subject key has been shredded or
    the ciphertext otherwise fails to decrypt."""
    key = keystore.get_key(subject_id)
    if key is None:
        return None
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        return f.decrypt(ciphertext)
    except InvalidToken:
        return None
