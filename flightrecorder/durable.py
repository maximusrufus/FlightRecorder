"""Durable state for plans.json via GCS snapshot-on-write / restore-on-boot.

Cloud Run's filesystem is in-memory and ephemeral: every revision deploy,
scale-to-zero, or crash destroys `plans.json` -- silently dropping a paying
tenant back to the free tier and losing the Stripe webhook idempotency
record (`__stripe_events__`), so a replayed webhook gets re-fulfilled.

This module snapshots the whole `plans.json` file into Google Cloud Storage
after every write, and restores it before the first read in a process --
using the object `generation` as a compare-and-swap guard so an overlapping
old/new revision during a rollout can never silently clobber the other's
writes.

Inert unless FLIGHTRECORDER_GCS_BUCKET is set: no import-time GCS client
construction, no `google.cloud.storage` import at all unless the bucket is
configured, no behavior change for local dev or the existing test suite.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger("flightrecorder.durable")

_MAX_QUIET_BYTES = 20 * 1024 * 1024  # 20 MB -- log a warning above this, not a failure.

_lock = threading.RLock()  # RLock: persist() re-enters restore_once() on a stale write
_client = None  # google.cloud.storage.Client, cached
_blob = None  # google.cloud.storage.Blob, cached
_generation = 0  # last known object generation; 0 == "object does not exist yet"
_restored = False


class StaleStateError(Exception):
    """Raised when a write's GCS upload lost a compare-and-swap race.

    This can only happen during the seconds-long overlap of a Cloud Run
    rollout where an old and a new revision are both briefly live. The local
    write that lost is intentionally discarded here; the caller (or Stripe's
    own webhook retry) replays the request against the winner's state.
    """


def gcs_bucket_name() -> str | None:
    return os.environ.get("FLIGHTRECORDER_GCS_BUCKET") or None


def gcs_object_name() -> str:
    return os.environ.get("FLIGHTRECORDER_GCS_OBJECT", "plans.json")


def is_active() -> bool:
    return bool(gcs_bucket_name())


def _get_blob():
    """Return the cached blob, constructing it (and the client) on first use."""
    global _client, _blob
    if _blob is None:
        from google.cloud import storage  # imported lazily so it's optional locally

        _client = storage.Client()
        bucket = _client.bucket(gcs_bucket_name())
        _blob = bucket.blob(gcs_object_name())
    return _blob


def _reset_client_cache() -> None:
    """Test hook: drop the cached client/blob so a fake can be installed."""
    global _client, _blob
    _client = None
    _blob = None


def restore_once(path: str) -> None:
    """Restore `path` from GCS if this process hasn't already done so.

    Must be called before the first read of `path`. Downloads to a sibling
    temp file and atomically `os.replace()`s it into position so a
    concurrent reader never observes a partially-written file.
    """
    global _generation, _restored
    with _lock:
        if _restored:
            return

        blob = _get_blob()
        try:
            blob.reload()
        except Exception as exc:
            from google.api_core.exceptions import NotFound

            if isinstance(exc, NotFound):
                _generation = 0
                _restored = True
                logger.info("durable state: no existing object, starting fresh")
                return
            logger.error("durable state: restore failed: %s", exc)
            raise

        tmp_path = f"{path}.download.tmp"
        try:
            blob.download_to_filename(tmp_path)
        except Exception as exc:
            logger.error("durable state: download failed: %s", exc)
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise

        try:
            os.replace(tmp_path, path)
        except OSError as exc:
            logger.warning(
                "durable state: could not swap in downloaded file (will retry next call): %s",
                exc,
            )
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return

        _generation = blob.generation
        _restored = True
        logger.info("durable state: restored %s (generation=%s)", path, _generation)


def persist(path: str) -> None:
    """Upload the current bytes of `path` to GCS, guarded by if_generation_match.

    Caller must hold the same FileLock guarding the write to `path` so a
    concurrent writer in this process (or another process) cannot interleave
    between the write and the upload.
    """
    global _generation

    data = Path(path).read_bytes()

    size = len(data)
    if size > _MAX_QUIET_BYTES:
        logger.warning("durable state: snapshot is %d bytes (>20MB) -- revisit the design", size)

    from google.api_core.exceptions import PreconditionFailed

    with _lock:
        blob = _get_blob()
        try:
            blob.upload_from_string(
                data,
                if_generation_match=_generation,
                content_type="application/json",
            )
        except PreconditionFailed as exc:
            logger.error(
                "durable state: stale generation on upload (expected %s): %s",
                _generation,
                exc,
            )
            # Another writer won the race. Discard this write, force a fresh
            # restore so the local file matches the winner, and let the
            # caller's retry (Stripe's webhook retry, or the HTTP client)
            # replay against that winner's state.
            global _restored
            _restored = False
            restore_once(path)
            raise StaleStateError(str(exc)) from exc

        _generation = blob.generation
        logger.info(
            "durable state: uploaded snapshot (%d bytes, generation=%s)",
            size,
            _generation,
        )
