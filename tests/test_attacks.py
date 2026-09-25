"""Regression tests converted directly from the adversarial verifier's
attack scripts (2026-09-13). Each of these must now FAIL (i.e. the
assertion below proves the attack no longer works). Cross-references:

  Attack 1 (tail truncation)          -> tests/test_checkpoint.py
  Attack 2 (hardcoded dev signing key) -> tests/test_startup_refusal.py
  Attack 3 (export pubkey swap)        -> tests/test_key_rotation.py
  Attack 4 (no auth / tenant isolation) -> tests/test_auth.py
  Attack 5 (HKDF-rederive shredded key) -> this file
  Attack 7 (duplicate seq / size cap)   -> this file + test_size_cap.py
  Attack 8 (OTel malformed payloads)    -> this file
"""

import base64

from cryptography.fernet import InvalidToken

from flightrecorder import crypto
from flightrecorder import ledger as L


def test_attack5_hkdf_rederivation_of_shredded_key_now_fails():
    """Original finding: the subject key was HKDF-derived from the master
    key, so an attacker who knows the master key + subject_id could
    re-derive the "shredded" key and decrypt anyway. Data keys are now
    os.urandom(32) -- structurally unrelated to the KEK -- so no derivation
    from the KEK can ever reproduce them."""
    keystore = crypto.Keystore(_scratch_keystore_path())
    subject = "acme:a1"
    raw_key = keystore.get_or_create_key(subject)

    f = crypto.Fernet(base64.urlsafe_b64encode(raw_key))
    ciphertext = f.encrypt(b"sensitive prompt")

    keystore.shred(subject)

    # The attack: attacker knows the KEK (assume total compromise) and the
    # subject id, and tries the OLD attack of HKDF-deriving a key from it.
    # There is no HKDF subject-key derivation function left in this
    # codebase at all -- confirm the module no longer exposes one, and
    # confirm that guessing the KEK itself cannot decrypt (KEK only wraps
    # keys, it never IS a data key).
    assert not hasattr(crypto, "_hkdf"), (
        "an HKDF subject-key derivation function must not exist"
    )

    kek_as_fernet_key = base64.urlsafe_b64encode(crypto._kek())
    forged_fernet = crypto.Fernet(kek_as_fernet_key)
    try:
        forged_fernet.decrypt(ciphertext)
        assert False, "KEK must never be usable to decrypt subject payloads directly"
    except InvalidToken:
        pass  # expected: KEK is not a data key

    # And the legitimate path is also gone, by construction:
    assert keystore.get_key(subject) is None


def _scratch_keystore_path():
    import tempfile
    import uuid

    return f"{tempfile.gettempdir()}/flightrecorder_attack5_{uuid.uuid4().hex}.keys.json"


def test_attack7_duplicate_seq_with_valid_hash_and_sig_detected(tmp_ledger_path):
    led = L.Ledger(tmp_ledger_path)
    led.append(
        tenant="acme",
        agent_id="a1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"one",
    )
    recs = list(led.read_all())

    dup = dict(recs[0])
    dup["ts"] = "1999-01-01T00:00:00+00:00"
    h = L.record_hash(dup)
    dup["hash"] = h
    dup["sig"] = crypto.sign(bytes.fromhex(h))

    result = L.verify_records([recs[0], dup], public_key_hex=crypto.public_key_hex())
    assert not result.ok, (
        "a second record claiming the same seq must be rejected as out-of-order"
    )


def test_attack7_oversized_payload_rejected(tmp_ledger_path, monkeypatch):
    monkeypatch.setenv("FLIGHTRECORDER_MAX_PAYLOAD_BYTES", str(1024 * 1024))
    led = L.Ledger(tmp_ledger_path)
    huge = b"A" * (2 * 1024 * 1024)
    try:
        led.append(
            tenant="acme",
            agent_id="a1",
            model="m",
            model_version="v1",
            kind="prompt",
            payload=huge,
        )
        assert False, "oversized payload must be rejected"
    except L.LedgerError:
        pass


def test_attack8_otel_malformed_payloads_do_not_crash_server(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import flightrecorder.proxy as proxy_mod
    from flightrecorder.auth import KeyStore

    monkeypatch.setattr(proxy_mod, "LEDGER_PATH", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(proxy_mod, "KEYS_PATH", str(tmp_path / "api_keys.json"))
    monkeypatch.setattr(proxy_mod, "PLANS_PATH", str(tmp_path / "plans.json"))
    monkeypatch.setattr(proxy_mod, "WITNESS_DIR", str(tmp_path / "witness"))
    proxy_mod._ledger = None
    proxy_mod._keystore = None
    proxy_mod._witness = None
    proxy_mod._plans = None

    keystore = KeyStore(str(tmp_path / "api_keys.json"))
    raw_key = keystore.create_key("t")
    client = TestClient(proxy_mod.app)
    headers = {"Authorization": f"Bearer {raw_key}"}

    r = client.post(
        "/v1/otel", json={"agent_id": "a", "attributes": {}}, headers=headers
    )
    assert r.status_code == 400

    r2 = client.post(
        "/v1/otel",
        json={
            "agent_id": "a",
            "attributes": {"gen_ai.prompt": {"nested": {"a": [1, 2, {"b": None}]}}},
        },
        headers=headers,
    )
    assert r2.status_code == 200

    r4 = client.post(
        "/v1/otel",
        json={
            "agent_id": "a",
            "attributes": {"gen_ai.prompt": 12345, "gen_ai.tool.arguments": [1, 2, 3]},
        },
        headers=headers,
    )
    assert r4.status_code == 200

    # Server must still be alive and answering after all of the above.
    still_alive = client.get("/v1/verify", headers=headers)
    assert still_alive.status_code == 200
