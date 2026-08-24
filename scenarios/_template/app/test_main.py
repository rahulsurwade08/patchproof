"""Minimal test suite for the scenario service contract.

Run inside the sandbox after any patch attempt:
    python -m pytest test_main.py -q
"""


def test_health():
    from fastapi.testclient import TestClient
    import main

    client = TestClient(main.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
