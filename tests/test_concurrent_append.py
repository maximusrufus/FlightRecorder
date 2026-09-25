import multiprocessing

from flightrecorder import crypto
from flightrecorder.ledger import Ledger, verify_records
from tests._concurrent_worker import append_n

N_WORKERS = 4
N_PER_WORKER = 15


def test_concurrent_appends_from_4_processes_are_gapfree(
    tmp_ledger_path, real_keys_env
):
    ledger_path = str(tmp_ledger_path)
    # Ensure the ledger file (and its lock sidecar) exist before forking.
    Ledger(ledger_path)

    procs = [
        multiprocessing.Process(target=append_n, args=(ledger_path, wid, N_PER_WORKER))
        for wid in range(N_WORKERS)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0

    led = Ledger(ledger_path)
    records = list(led.read_all())
    assert len(records) == N_WORKERS * N_PER_WORKER

    seqs = sorted(r["seq"] for r in records)
    assert seqs == list(range(1, N_WORKERS * N_PER_WORKER + 1)), (
        "seq must be gap-free and contiguous"
    )

    result = verify_records(records, public_key_hex=crypto.public_key_hex())
    assert result.ok
