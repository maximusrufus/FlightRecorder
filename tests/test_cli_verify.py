"""Tests for `flightrecorder verify` (the top-level CLI): exit 0 on an
intact ledger, exit 2 after flipping one byte of a valid record line."""

from __future__ import annotations

from flightrecorder import cli
from flightrecorder import ledger as ledger_mod


def _build_ledger(tmp_path):
    path = tmp_path / "ledger.jsonl"
    led = ledger_mod.Ledger(path)
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="1",
        kind="prompt",
        payload=b"hello",
    )
    led.append(
        tenant="acme",
        agent_id="agent-1",
        model="m",
        model_version="1",
        kind="output",
        payload=b"world",
    )
    return path


def test_verify_exits_0_on_intact_ledger(tmp_path):
    path = _build_ledger(tmp_path)
    exit_code = cli.main(["verify", str(path)])
    assert exit_code == 0


def test_verify_exits_2_on_tampered_ledger(tmp_path):
    path = _build_ledger(tmp_path)

    # Flip one byte in the middle of the file (inside the first record line).
    data = bytearray(path.read_bytes())
    # find a byte that is an ASCII letter to flip safely without breaking JSON structure characters
    for i, b in enumerate(data):
        if 97 <= b <= 122:  # a-z
            data[i] = b ^ 0x01
            break
    path.write_bytes(bytes(data))

    exit_code = cli.main(["verify", str(path)])
    assert exit_code == 2


def test_verify_exits_1_on_missing_file(tmp_path):
    exit_code = cli.main(["verify", str(tmp_path / "does_not_exist.jsonl")])
    assert exit_code == 1
