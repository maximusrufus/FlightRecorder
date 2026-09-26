"""Tests for flightrecorder.durable -- snapshot-on-write / restore-on-boot
for plans.json. All GCS access is faked in-process; nothing here touches
the network."""

from __future__ import annotations

import json

import pytest

# The GCS client is an OPTIONAL extra: this package must install and run with no
# cloud SDK present, so the test that exercises the fake-GCS path skips instead
# of breaking collection for anyone doing a minimal install.
_api_core = pytest.importorskip(
    "google.api_core.exceptions", reason="google-cloud-storage extra not installed"
)
NotFound = _api_core.NotFound
PreconditionFailed = _api_core.PreconditionFailed

from flightrecorder import durable  # noqa: E402
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


def _upload_count(monkeypatch, store: dict) -> list[int]:
    calls: list[int] = []
    original = FakeBlob.upload_from_string

    def counted(self, data, if_generation_match=None, content_type=None):
        calls.append(1)
        return original(
            self, data, if_generation_match=if_generation_match, content_type=content_type
        )

    monkeypatch.setattr(FakeBlob, "upload_from_string", counted)
    return calls


def test_plan_change_uploads_once(tmp_path, fake_gcs, monkeypatch):
    calls = _upload_count(monkeypatch, fake_gcs)
    store = PlanStore(tmp_path / "plans.json")
    calls.clear()  # constructor may have written the initial "{}"
    store.set_plan("acme", "pro")
    assert len(calls) == 1


def test_read_uploads_nothing(tmp_path, fake_gcs, monkeypatch):
    store = PlanStore(tmp_path / "plans.json")
    store.set_plan("acme", "pro")
    calls = _upload_count(monkeypatch, fake_gcs)
    assert store.get_plan("acme") == "pro"
    assert len(calls) == 0


def test_fresh_process_restores_plan(tmp_path, fake_gcs):
    store1 = PlanStore(tmp_path / "a.json")
    store1.set_plan("acme", "business")

    # Simulate a brand-new process/instance: reset the restored flag and
    # point at a fresh local path, as a fresh Cloud Run instance would.
    durable._restored = False
    store2 = PlanStore(tmp_path / "a2.json")
    assert store2.get_plan("acme") == "business"


def test_stale_generation_raises_and_resyncs(tmp_path, fake_gcs, monkeypatch):
    path = tmp_path / "f.json"
    store = PlanStore(path)
    store.set_plan("acme", "core")  # generation now 1

    # Another writer wins the race: its snapshot (plan "winner") lands in
    # the bucket with a bumped generation, behind our back.
    winner_data = json.dumps({"winner": {"plan": "business", "usage": {}}}).encode("utf-8")
    fake_gcs["data"] = winner_data
    fake_gcs["generation"] = fake_gcs["generation"] + 1

    with pytest.raises(durable.StaleStateError):
        store.set_plan("acme", "pro")

    # The local file now matches the winner's state, not the discarded write.
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert "winner" in on_disk
    assert on_disk.get("acme", {}).get("plan") != "pro"


def test_inactive_when_bucket_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("FLIGHTRECORDER_GCS_BUCKET", raising=False)
    store = PlanStore(tmp_path / "h.json")
    store.set_plan("acme", "pro")
    assert store.get_plan("acme") == "pro"


def test_stripe_event_idempotency_survives_restart(tmp_path, fake_gcs):
    path1 = tmp_path / "e1.json"
    store1 = PlanStore(path1)
    assert store1.mark_event_processed("evt_123") is True

    # Simulate a restart: new process, fresh local path.
    durable._restored = False
    path2 = tmp_path / "e2.json"
    store2 = PlanStore(path2)
    # Replayed webhook delivery of the same event id must still be detected
    # as a duplicate after the restart.
    assert store2.mark_event_processed("evt_123") is False
