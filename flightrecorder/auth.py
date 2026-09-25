"""Per-tenant API keys.

Only sha256(key) is ever stored — the raw key is shown once, at creation
time, by the admin CLI, and never again. Tenant is DERIVED from the key
(looked up via its hash); it is never taken from request bodies, so a
caller cannot claim to be a different tenant than the key they hold.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from flightrecorder.filelock import FileLock

KEY_PREFIX = "fr_live_"


def generate_raw_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class KeyStore:
    """File-backed JSON store: sha256(key) -> {tenant, created_at}."""

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
        os.replace(tmp, self.path)

    def create_key(self, tenant: str) -> str:
        raw_key = generate_raw_key()
        key_hash = hash_key(raw_key)
        with FileLock(self.path):
            data = self._read()
            data[key_hash] = {"tenant": tenant, "created_at": time.time()}
            self._write(data)
        return raw_key

    def revoke_key(self, raw_key: str) -> bool:
        key_hash = hash_key(raw_key)
        with FileLock(self.path):
            data = self._read()
            if key_hash in data:
                del data[key_hash]
                self._write(data)
                return True
            return False

    def tenant_for_key(self, raw_key: str) -> Optional[str]:
        key_hash = hash_key(raw_key)
        data = self._read()
        entry = data.get(key_hash)
        return entry.get("tenant") if entry else None
