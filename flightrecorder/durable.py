"""Durable state for the whole data directory via GCS snapshot/restore.

Cloud Run's filesystem is in-memory and ephemeral: every revision deploy,
scale-to-zero, or crash destroys everything under `FLIGHTRECORDER_DATA_DIR`
-- the ledger (the product itself), the anchor log, the checkpoint witness
store, the customer API-key store, and the plan/usage store. Losing the key
store alone means NO customer can authenticate after a deploy; losing the
ledger loses the audit trail it exists to protect.

These files must be mutually consistent with each other (a key that exists
must have a plan; a ledger record must not reference a tenant the key store
has since lost), so this module snapshots the ENTIRE data directory as a
single tar.gz object rather than snapshotting files independently -- one
object means one GCS `generation` and therefore one consistent point in
time across all of them.

Inert unless FLIGHTRECORDER_GCS_BUCKET is set: no import-time GCS client
construction, no `google.cloud.storage` import at all unless the bucket is
configured, no behavior change for local dev or the existing test suite.

GROWTH CEILING: this design re-uploads the ENTIRE data directory on every
mutating write, so per-write upload cost is O(total state size), not O(what
changed). That is fine while the tarball stays comfortably under the 20MB
warning threshold below and write volume stays modest -- each write now
costs a full-directory round trip to GCS, so this does not scale to a
sustained high-throughput ledger. Once a tenant's data directory approaches
that ceiling (or writes need to be much faster than one full upload allows),
this needs to become incremental (per-file objects + a manifest, WAL
shipping, or a real database with a managed durability layer) -- not a
bigger tarball. Not building that now; just naming the wall.
"""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import threading
from io import BytesIO
from pathlib import Path

logger = logging.getLogger("flightrecorder.durable")

_MAX_QUIET_BYTES = 20 * 1024 * 1024  # 20 MB -- log a warning above this, not a failure.

# Files that are never part of the durable snapshot: in-flight atomic-write
# temp files (`*.tmp.<pid>`, from the `_write` helpers in plans.py/auth.py),
# and FileLock sidecar files (`*.lock`) -- both are per-process ephemera
# that a fresh instance recreates on demand, and restoring a stale `.lock`
# would just make the new instance wait out its own stale-lock timeout.
_SKIP_SUFFIXES = (".lock",)
_SKIP_MARKERS = (".tmp.", ".download.tmp", ".restore.old.")


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
    return os.environ.get("FLIGHTRECORDER_GCS_OBJECT", "state.tar.gz")


def data_root() -> str:
    """The directory this module snapshots. Single source of truth so callers
    outside proxy.py do not re-derive it and drift."""
    return os.getenv("FLIGHTRECORDER_DATA_DIR", "./data")


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


def _should_skip(path: Path) -> bool:
    if path.suffix in _SKIP_SUFFIXES:
        return True
    name = path.name
    s = str(path)
    return any(marker in name or marker in s for marker in _SKIP_MARKERS)


def _build_archive(root: Path) -> bytes:
    """Deterministic tar.gz of every file under `root`: sorted member order,
    fixed per-entry metadata (mtime/uid/gid/uname/gname), fixed gzip mtime --
    identical directory content always yields identical bytes."""
    files = sorted(
        (p for p in root.rglob("*") if p.is_file() and not _should_skip(p)),
        key=lambda p: p.relative_to(root).as_posix(),
    )

    buf = BytesIO()
    # gzip's own header carries a timestamp; fix it so re-running persist()
    # over unchanged content reproduces identical bytes (verified by a test).
    import gzip

    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for p in files:
                arcname = p.relative_to(root).as_posix()
                info = tarfile.TarInfo(name=arcname)
                info.size = p.stat().st_size
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o644
                with open(p, "rb") as f:
                    tf.addfile(info, f)
    return buf.getvalue()


def _safe_extract(tar_bytes: bytes, dest: Path) -> None:
    """Extract `tar_bytes` into `dest`, refusing any member whose resolved
    path would land outside `dest` (path traversal) -- even though we wrote
    the archive ourselves, a corrupted or substituted object should not be
    able to write outside the intended tree."""
    dest_resolved = dest.resolve()
    with tarfile.open(fileobj=BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                logger.error(
                    "durable state: refusing tar member %r -- resolves outside %s",
                    member.name,
                    dest_resolved,
                )
                continue
            tf.extract(member, path=dest, set_attrs=False)


def restore_once(root: str) -> None:
    """Restore the data directory `root` from GCS if this process hasn't
    already done so. Must be called before the first read of ANY store
    living under `root` (ledger, anchors, witness, keys, plans).

    Downloads into a temp sibling directory first, then atomically swaps it
    into place, so a partial download or a crash mid-restore can never leave
    `root` half-written.
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

        root_path = Path(root)
        tmp_tarball = f"{root}.download.tmp.tar.gz"
        tmp_dir = Path(f"{root}.download.tmp")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        try:
            os.remove(tmp_tarball)
        except OSError:
            pass

        try:
            blob.download_to_filename(tmp_tarball)
            tmp_dir.mkdir(parents=True, exist_ok=True)
            with open(tmp_tarball, "rb") as f:
                _safe_extract(f.read(), tmp_dir)
        except Exception as exc:
            logger.error("durable state: download/extract failed: %s", exc)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            try:
                os.remove(tmp_tarball)
            except OSError:
                pass
            raise
        finally:
            try:
                os.remove(tmp_tarball)
            except OSError:
                pass

        # Swap the freshly-extracted tree into place. Rename the old
        # directory aside first (if present) rather than deleting it before
        # we know the swap will succeed, so a failed os.replace can put it
        # back instead of leaving `root` empty.
        backup = Path(f"{root}.restore.old.{os.getpid()}")
        shutil.rmtree(backup, ignore_errors=True)
        had_existing = root_path.exists()
        if had_existing:
            os.replace(root_path, backup)
        else:
            root_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(tmp_dir, root_path)
        except OSError as exc:
            logger.error("durable state: could not swap in restored directory: %s", exc)
            if had_existing:
                os.replace(backup, root_path)
            raise
        if had_existing:
            shutil.rmtree(backup, ignore_errors=True)

        _generation = blob.generation
        _restored = True
        logger.info("durable state: restored %s (generation=%s)", root, _generation)


def persist(root: str) -> None:
    """Upload a fresh snapshot of the directory `root` to GCS.

    Caller must hold whatever FileLock guards the write that triggered this,
    so a concurrent writer in this process cannot interleave between the
    write and the upload.
    """
    global _generation

    data = _build_archive(Path(root))

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
                content_type="application/gzip",
            )
        except PreconditionFailed as exc:
            logger.error(
                "durable state: stale generation on upload (expected %s): %s",
                _generation,
                exc,
            )
            # Another writer won the race. Discard this write, force a fresh
            # restore so the local tree matches the winner, and let the
            # caller's retry (Stripe's webhook retry, or the HTTP client)
            # replay against that winner's state.
            global _restored
            _restored = False
            restore_once(root)
            raise StaleStateError(str(exc)) from exc

        _generation = blob.generation
        logger.info(
            "durable state: uploaded snapshot (%d bytes, generation=%s)",
            size,
            _generation,
        )
