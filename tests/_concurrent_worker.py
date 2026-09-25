"""Module-level worker for the concurrent-append test (must be importable
by name for multiprocessing to pickle it on Windows' spawn start method)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flightrecorder.ledger import Ledger  # noqa: E402


def append_n(ledger_path: str, worker_id: int, n: int) -> None:
    led = Ledger(ledger_path)
    for i in range(n):
        led.append(
            tenant="acme",
            agent_id=f"worker-{worker_id}",
            model="m",
            model_version="v1",
            kind="prompt",
            payload=f"w{worker_id}-{i}".encode(),
        )
