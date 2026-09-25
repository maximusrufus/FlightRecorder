"""Flight Recorder — a tamper-evident, cryptographically signed,
regulator-exportable audit trail for AI agents.

    from flightrecorder import Recorder
    rec = Recorder()
    rec.record(kind="prompt", payload="hello")

Standalone package. No dependency on any other repo in this workspace; any
shared logic (hash-chain, Ed25519 signing, RFC 3161 anchoring) is vendored
and adapted here.
"""

from .recorder import Recorder, RecorderError

__version__ = "0.1.0"
__all__ = ["Recorder", "RecorderError", "__version__"]
