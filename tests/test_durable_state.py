"""Tests for flightrecorder.durable -- whole-data-directory snapshot/restore.

plans.json, api_keys.json, ledger.jsonl and anchors.jsonl must stay mutually
consistent (a key must have a plan; a ledger record must not outlive the key
store that authenticated it), so durable.py snapshots the ENTIRE data
directory as one tar.gz object rather than snapshotting files independently.

All GCS access is faked in-process; nothing here touches the network.
"""

from __future__ import annotations

import io
import tarfile

import pytest

# The whole file exercises the optional GCS durability path; skip cleanly
# (not a failure) in an environment that never installed
# google-cloud-storage -- FlightRecorder itself imports it lazily and only
# when FLIGHTRECORDER_GCS_BUCKET is set (see flightrecorder/durable.py).
google_api_core_exceptions = pytest.importorskip("google.api_core.exceptions")
NotFound = google_api_core_exceptions.NotFound
PreconditionFailed = google_api_core_exceptions.PreconditionFailed

from flightrecorder import crypto, durable  # noqa: E402
from flightrecorder.auth import KeyStore  # noqa: E402
from flightrecorder.ledger import Ledger, verify_records  # noqa: E402
from flightrecorder.plans import PlanStore  # noqa: E402


class FakeBlob:
    def __init__(self, store: dict):
        self._store = store
        self.generation = 0

    def reload(self) -> None:
        if "data" not in self._store:
            raise NotFound("no such object")
        self.generation = self._store["generation"]

    def download_to_filename(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(self._store["data"])

    def upload_from_string(self, data, if_generation_match=None, content_type=None) -> None:
        current = self._store.get("generation", 0)
        if if_generation_match is not None and if_generation_match != current:
            raise PreconditionFailed("generation mismatch")
        new_generation = current + 1
        self._store["data"] = bytes(data)
        self._store["generation"] = new_generation
        self.generation = new_generation


@pytest.fixture()
def fake_gcs(monkeypatch):
    """Install a fake blob backed by a shared dict, and activate durability."""
    store: dict = {}
    monkeypatch.setenv("FLIGHTRECORDER_GCS_BUCKET", "fake-bucket")
    durable._reset_client_cache()
    durable._generation = 0
    durable._restored = False

    def fake_get_blob():
        return FakeBlob(store)

    monkeypatch.setattr(durable, "_get_blob", fake_get_blob)
    yield store
    monkeypatch.delenv("FLIGHTRECORDER_GCS_BUCKET", raising=False)
    durable._reset_client_cache()
    durable._generation = 0
    durable._restored = False


def _upload_count(monkeypatch, store: dict) -> list[bytes]:
    """Wrap FakeBlob.upload_from_string to record every uploaded payload."""
    calls: list[bytes] = []
    original = FakeBlob.upload_from_string

    def counted(self, data, if_generation_match=None, content_type=None):
        calls.append(bytes(data))
        return original(
            self, data, if_generation_match=if_generation_match, content_type=content_type
        )

    monkeypatch.setattr(FakeBlob, "upload_from_string", counted)
    return calls


def _new_process(monkeypatch=None) -> None:
    """Simulate a fresh Cloud Run instance: this process hasn't restored yet."""
    durable._restored = False


def test_key_written_then_fresh_process_resolves_tenant(tmp_path, fake_gcs):
    root1 = tmp_path / "instance_a"
    store1 = KeyStore(root1 / "api_keys.json")
    raw_key = store1.create_key("acme")

    _new_process()
    root2 = tmp_path / "instance_b"
    store2 = KeyStore(root2 / "api_keys.json")
    assert store2.tenant_for_key(raw_key) == "acme"


def test_ledger_record_survives_restart_and_chain_verifies(tmp_path, fake_gcs):
    root1 = tmp_path / "instance_a"
    led1 = Ledger(root1 / "ledger.jsonl")
    led1.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"hello",
    )

    _new_process()
    root2 = tmp_path / "instance_b"
    led2 = Ledger(root2 / "ledger.jsonl")
    records = list(led2.read_all())
    assert len(records) == 1
    assert records[0]["tenant"] == "acme"

    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert result.ok
    assert result.n_records == 1


def test_keys_plans_and_ledger_restore_together_from_one_object(tmp_path, fake_gcs):
    root1 = tmp_path / "instance_a"
    keys1 = KeyStore(root1 / "api_keys.json")
    plans1 = PlanStore(root1 / "plans.json")
    ledger1 = Ledger(root1 / "ledger.jsonl")

    raw_key = keys1.create_key("acme")
    plans1.set_plan("acme", "pro")
    ledger1.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"hi",
    )

    _new_process()
    root2 = tmp_path / "instance_b"
    # Constructing the FIRST store against the new root restores the WHOLE
    # directory; the other two just find their files already there.
    keys2 = KeyStore(root2 / "api_keys.json")
    plans2 = PlanStore(root2 / "plans.json")
    ledger2 = Ledger(root2 / "ledger.jsonl")

    assert keys2.tenant_for_key(raw_key) == "acme"
    assert plans2.get_plan("acme") == "pro"
    assert len(list(ledger2.read_all())) == 1


def test_tar_member_with_path_traversal_is_refused(tmp_path, fake_gcs):
    # Craft a malicious archive with a legitimate member plus a `../` escape.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        good = b'{"tenant": "acme"}'
        info = tarfile.TarInfo(name="plans.json")
        info.size = len(good)
        tf.addfile(info, io.BytesIO(good))

        evil = b"pwned"
        evil_info = tarfile.TarInfo(name="../../evil.txt")
        evil_info.size = len(evil)
        tf.addfile(evil_info, io.BytesIO(evil))

    fake_gcs["data"] = buf.getvalue()
    fake_gcs["generation"] = 1

    root = tmp_path / "victim"
    durable.restore_once(str(root))

    assert (root / "plans.json").exists()
    assert not (tmp_path / "evil.txt").exists()
    escaped = list(tmp_path.parent.glob("evil.txt"))
    assert escaped == []


def test_two_successive_persists_produce_identical_bytes(tmp_path, fake_gcs, monkeypatch):
    root = tmp_path / "instance_a"
    store = PlanStore(root / "plans.json")
    store.set_plan("acme", "pro")  # first real write -> first persist

    calls = _upload_count(monkeypatch, fake_gcs)
    # Two persists over UNCHANGED content must produce byte-identical
    # payloads (sorted member order, fixed per-entry + gzip metadata).
    durable.persist(str(root))
    durable.persist(str(root))
    assert len(calls) == 2
    assert calls[0] == calls[1]


def test_read_only_uploads_nothing(tmp_path, fake_gcs, monkeypatch):
    root = tmp_path / "instance_a"
    store = KeyStore(root / "api_keys.json")
    raw_key = store.create_key("acme")

    calls = _upload_count(monkeypatch, fake_gcs)
    assert store.tenant_for_key(raw_key) == "acme"
    assert len(calls) == 0


def test_inactive_when_bucket_unset_no_upload_no_import(tmp_path, monkeypatch):
    monkeypatch.delenv("FLIGHTRECORDER_GCS_BUCKET", raising=False)

    def _boom():
        raise AssertionError("_get_blob() must never be called when inactive")

    monkeypatch.setattr(durable, "_get_blob", _boom)

    root = tmp_path / "instance_a"
    plans = PlanStore(root / "plans.json")
    plans.set_plan("acme", "pro")
    assert plans.get_plan("acme") == "pro"

    keys = KeyStore(root / "api_keys.json")
    raw_key = keys.create_key("acme")
    assert keys.tenant_for_key(raw_key) == "acme"

    led = Ledger(root / "ledger.jsonl")
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"hi",
    )
    assert len(list(led.read_all())) == 1
