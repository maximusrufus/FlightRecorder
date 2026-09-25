"""Minimal cross-platform, cross-process exclusive file lock, stdlib-only.

Used to serialize appends to the ledger JSONL file across multiple OS
processes (not just threads within one process). Implemented as a
lockfile-based spinlock using `os.open(..., O_CREAT | O_EXCL)` so it works
identically on Windows and POSIX without a third-party dependency.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional


class LockTimeout(RuntimeError):
    pass


class FileLock:
    """Exclusive lock backed by an `.lock` sidecar file.

    Usage:
        with FileLock(path_to_ledger):
            ... critical section spanning multiple processes ...
    """

    def __init__(
        self, target_path: str | Path, timeout: float = 30.0, poll: float = 0.02
    ):
        self.lock_path = Path(str(target_path) + ".lock")
        self.timeout = timeout
        self.poll = poll
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(
                    str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR
                )
                try:
                    os.write(self._fd, str(os.getpid()).encode("ascii"))
                except OSError:
                    pass
                return
            except (FileExistsError, PermissionError):
                # On Windows, a lock file mid delete-then-recreate (this
                # class's own release()->next acquire() race across two
                # processes) can transiently surface as PermissionError
                # (WinError 5 / ERROR_ACCESS_DENIED) instead of a clean
                # FileExistsError -- NTFS briefly refuses a create while a
                # delete on the same name is still completing. It is not a
                # real "someone else has an unrelated lock" condition, just
                # an imprecise errno; treat it identically to "still locked,
                # retry" rather than letting it escape as a hard failure.
                if time.monotonic() >= deadline:
                    # Stale-lock recovery: if the lock file is far older than any
                    # sane critical section, assume the holder died and steal it.
                    try:
                        age = time.time() - self.lock_path.stat().st_mtime
                    except OSError:
                        age = 0.0
                    if age > max(self.timeout * 4, 5.0):
                        try:
                            os.remove(self.lock_path)
                        except OSError:
                            pass
                        continue
                    raise LockTimeout(
                        f"could not acquire lock {self.lock_path} within {self.timeout}s"
                    )
                time.sleep(self.poll)

    def release(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        try:
            os.remove(self.lock_path)
        except OSError:
            pass

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
