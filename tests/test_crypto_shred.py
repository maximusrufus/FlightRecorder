from flightrecorder import crypto
from flightrecorder.ledger import Ledger, verify_records


def test_crypto_shred_keeps_chain_valid_but_payload_unreadable(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"sensitive prompt content",
        subject_id="client-42",
    )
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="output",
        payload=b"sensitive output content",
        subject_id="client-42",
    )

    records = list(led.read_all())
    before = led.decrypt_record_payload(records[0])
    assert before == b"sensitive prompt content"

    # Chain verifies before shred.
    result_before = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert result_before.ok

    shredded = led.keystore.shred("client-42")
    assert shredded is True

    # Payload is now permanently unreadable...
    after = led.decrypt_record_payload(records[0])
    assert after is None

    # ...but the hash chain (computed over ciphertext) still verifies exactly
    # as before, byte for byte.
    records_after = list(led.read_all())
    result_after = verify_records(records_after, public_key_hex=crypto.public_key_hex())
    assert result_after.ok
    assert records_after == records


def test_shredding_unknown_subject_is_a_noop(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    assert led.keystore.shred("no-such-subject") is False
