"""Item 3: verify_cli requires an out-of-band trusted key/fingerprint, and
supports key rotation via signed key-transition records."""

import hashlib
import io
import json
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flightrecorder import crypto
from flightrecorder import ledger as L
from flightrecorder.verify_cli import (
    UsageError,
    verify_export,
)
from flightrecorder.verify_cli import (
    main as verify_cli_main,
)


def _build_zip(tmp_path, records, pub_hex, transitions=None, manifest=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "records.jsonl",
            "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n",
        )
        zf.writestr("chain_heads.json", "[]")
        zf.writestr("anchors.jsonl", "")
        zf.writestr("checkpoints.jsonl", "")
        zf.writestr("public_key.hex", pub_hex)
        zf.writestr("manifest.json", json.dumps(manifest or {}))
        if transitions:
            zf.writestr(
                "key_transitions.jsonl",
                "\n".join(json.dumps(t) for t in transitions) + "\n",
            )
    path = tmp_path / "export.zip"
    path.write_bytes(buf.getvalue())
    return path


def _one_record_chain(led_path):
    led = L.Ledger(led_path)
    led.append(
        tenant="acme",
        agent_id="a1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"hi",
    )
    return list(led.read_all())


def test_no_trusted_key_is_usage_error(tmp_path):
    records = _one_record_chain(tmp_path / "l.jsonl")
    zip_path = _build_zip(tmp_path, records, crypto.public_key_hex())
    try:
        verify_export(str(zip_path))
        assert False, "expected UsageError"
    except UsageError:
        pass

    exit_code = verify_cli_main([str(zip_path)])
    assert exit_code == 1


def test_matching_trusted_key_verifies(tmp_path):
    records = _one_record_chain(tmp_path / "l.jsonl")
    pub_hex = crypto.public_key_hex()
    zip_path = _build_zip(tmp_path, records, pub_hex)
    ok, msg = verify_export(str(zip_path), trusted_key=pub_hex)
    assert ok is True


def test_matching_trusted_fingerprint_verifies(tmp_path):
    records = _one_record_chain(tmp_path / "l.jsonl")
    pub_hex = crypto.public_key_hex()
    fingerprint = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
    zip_path = _build_zip(tmp_path, records, pub_hex)
    ok, msg = verify_export(str(zip_path), trusted_fingerprint=fingerprint)
    assert ok is True


def test_attacker_own_key_bundled_is_untrusted(tmp_path):
    """Regression for the adversarial finding: a fully forged export,
    self-consistently signed with the attacker's OWN key and bundling that
    key as public_key.hex, must be rejected once a real --trusted-key is
    supplied (previously verify_cli trusted whatever key shipped inside)."""
    attacker_priv = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    attacker_pub_hex = attacker_priv.public_key().public_bytes_raw().hex()

    forged = []
    prev_hash = L.GENESIS
    for i in range(3):
        rec = {
            "seq": i + 1,
            "ts": "2020-01-01T00:00:00+00:00",
            "tenant": "acme",
            "agent_id": "a1",
            "model": "m",
            "model_version": "v1",
            "kind": "prompt",
            "payload_hash": "0" * 64,
            "payload_enc": "Zm9yZ2Vk",
            "prev_hash": prev_hash,
            "subject_id": "acme:a1",
            "dev_mode": False,
        }
        h = L.record_hash(rec)
        rec["hash"] = h
        rec["sig"] = attacker_priv.sign(bytes.fromhex(h)).hex()
        forged.append(rec)
        prev_hash = h

    zip_path = _build_zip(tmp_path, forged, attacker_pub_hex)

    real_pub_hex = crypto.public_key_hex()
    ok, msg = verify_export(str(zip_path), trusted_key=real_pub_hex)
    assert ok is False
    assert "untrusted" in msg.lower()

    exit_code = verify_cli_main([str(zip_path), "--trusted-key", real_pub_hex])
    assert exit_code == 2


def test_key_rotation_chain_is_trusted(tmp_path):
    """Old key signs new key's hex; verify_cli should trust the export
    bundled under the NEW key when given the OLD key as --trusted-key."""
    old_priv = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
    new_priv = Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)
    old_pub_hex = old_priv.public_key().public_bytes_raw().hex()
    new_pub_hex = new_priv.public_key().public_bytes_raw().hex()

    transition_sig = old_priv.sign(new_pub_hex.encode("utf-8")).hex()
    transitions = [
        {"old_key_hex": old_pub_hex, "new_key_hex": new_pub_hex, "sig": transition_sig}
    ]

    # Records signed with the NEW key.
    records = []
    prev_hash = L.GENESIS
    for i in range(2):
        rec = {
            "seq": i + 1,
            "ts": "2026-01-01T00:00:00+00:00",
            "tenant": "acme",
            "agent_id": "a1",
            "model": "m",
            "model_version": "v1",
            "kind": "prompt",
            "payload_hash": "0" * 64,
            "payload_enc": "Zm9yZ2Vk",
            "prev_hash": prev_hash,
            "subject_id": "acme:a1",
            "dev_mode": False,
        }
        h = L.record_hash(rec)
        rec["hash"] = h
        rec["sig"] = new_priv.sign(bytes.fromhex(h)).hex()
        records.append(rec)
        prev_hash = h

    zip_path = _build_zip(tmp_path, records, new_pub_hex, transitions=transitions)

    ok, msg = verify_export(str(zip_path), trusted_key=old_pub_hex)
    assert ok is True, msg


def test_key_rotation_bogus_transition_not_trusted(tmp_path):
    """A transition record NOT actually signed by the claimed old key must
    not extend trust."""
    old_priv = Ed25519PrivateKey.from_private_bytes(b"\x04" * 32)
    new_priv = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    unrelated_priv = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
    old_pub_hex = old_priv.public_key().public_bytes_raw().hex()
    new_pub_hex = new_priv.public_key().public_bytes_raw().hex()

    # Signed by an unrelated key, not by old_priv -- forged transition.
    bogus_sig = unrelated_priv.sign(new_pub_hex.encode("utf-8")).hex()
    transitions = [
        {"old_key_hex": old_pub_hex, "new_key_hex": new_pub_hex, "sig": bogus_sig}
    ]

    records = [
        {
            "seq": 1,
            "ts": "2026-01-01T00:00:00+00:00",
            "tenant": "acme",
            "agent_id": "a1",
            "model": "m",
            "model_version": "v1",
            "kind": "prompt",
            "payload_hash": "0" * 64,
            "payload_enc": "Zm9yZ2Vk",
            "prev_hash": L.GENESIS,
            "subject_id": "acme:a1",
            "dev_mode": False,
        }
    ]
    h = L.record_hash(records[0])
    records[0]["hash"] = h
    records[0]["sig"] = new_priv.sign(bytes.fromhex(h)).hex()

    zip_path = _build_zip(tmp_path, records, new_pub_hex, transitions=transitions)
    ok, msg = verify_export(str(zip_path), trusted_key=old_pub_hex)
    assert ok is False
