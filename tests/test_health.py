from fastapi.testclient import TestClient

import flightrecorder.proxy as proxy_mod


def test_health():
    # Liveness path in production: Cloud Run's Google Front End does not
    # intercept /health (unlike /healthz in sibling services), so this is
    # the route ops should point monitors at.
    client = TestClient(proxy_mod.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
