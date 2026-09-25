"""The service refuses to start without real key material (item 2). Run in
a subprocess so we test an actual fresh module import, not a re-import of
an already-loaded module."""

import os
import subprocess
import sys


def test_proxy_refuses_to_start_without_keys():
    env = dict(os.environ)
    for var in ("FLIGHTRECORDER_DEV", "FLIGHTRECORDER_KEK", "FLIGHTRECORDER_SIGNING_KEY"):
        env.pop(var, None)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-c", "import flightrecorder.proxy"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert "FLIGHTRECORDER_KEK" in proc.stderr or "FLIGHTRECORDER_SIGNING_KEY" in proc.stderr


def test_proxy_starts_with_dev_flag():
    env = dict(os.environ)
    for var in ("FLIGHTRECORDER_KEK", "FLIGHTRECORDER_SIGNING_KEY"):
        env.pop(var, None)
    env["FLIGHTRECORDER_DEV"] = "1"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-c", "import flightrecorder.proxy; print('OK')"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "OK" in proc.stdout
