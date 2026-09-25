import json

from flightrecorder import crypto
from flightrecorder.ledger import Ledger, verify_records


def test_chain_verifies_after_appends(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    for i in range(5):
        led.append(
            tenant="acme",
            agent_id="agent-1",
            model="in-house-llm",
            model_version="v1",
            kind="prompt",
            payload=f"prompt {i}".encode(),
        )
    records = list(led.read_all())
    assert len(records) == 5
    assert [r["seq"] for r in records] == [1, 2, 3, 4, 5]

    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert result.ok
    assert result.n_records == 5


def test_tamper_a_byte_detected_at_correct_seq(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    for i in range(4):
        led.append(
            tenant="acme",
            agent_id="agent-1",
            model="m",
            model_version="v1",
            kind="output",
            payload=f"output {i}".encode(),
        )

    lines = tmp_ledger_path.read_text(encoding="utf-8").splitlines()
    # Tamper seq=3 (index 2): flip a character inside payload_hash field.
    rec = json.loads(lines[2])
    rec["payload_hash"] = "0" * 64
    lines[2] = json.dumps(rec)
    tmp_ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records = [json.loads(ln) for ln in lines]
    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert not result.ok
    assert result.bad_seq == 3


def test_deleting_a_line_detected(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    for i in range(4):
        led.append(
            tenant="acme",
            agent_id="agent-1",
            model="m",
            model_version="v1",
            kind="output",
            payload=f"o{i}".encode(),
        )
    lines = tmp_ledger_path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # delete seq=2
    records = [json.loads(ln) for ln in lines]
    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert not result.ok
    # remaining seq=3 has prev_hash pointing at deleted seq=2's hash -> break,
    # or the seq sequence itself jumps from 1 to 3.
    assert result.bad_seq in (2, 3)


def test_reorder_detected(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    for i in range(4):
        led.append(
            tenant="acme",
            agent_id="agent-1",
            model="m",
            model_version="v1",
            kind="output",
            payload=f"o{i}".encode(),
        )
    lines = tmp_ledger_path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # swap seq 2 and 3
    records = [json.loads(ln) for ln in lines]
    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert not result.ok


def test_signature_check_catches_forged_hash_and_sig(tmp_ledger_path):
    led = Ledger(tmp_ledger_path)
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="v1",
        kind="prompt",
        payload=b"hello",
    )
    records = list(led.read_all())
    # Forge a record with a self-consistent (but unsigned-by-us) hash chain:
    # recompute hash correctly but leave the old (now-invalid) signature.
    forged = dict(records[0])
    forged["payload_hash"] = "1" * 64
    from flightrecorder.ledger import record_hash

    forged["hash"] = record_hash(forged)  # hash matches now...
    # ...but sig still signs the OLD hash, so signature verification fails.
    result = verify_records([forged], public_key_hex=crypto.public_key_hex())
    assert not result.ok
    assert "signature" in result.reason
