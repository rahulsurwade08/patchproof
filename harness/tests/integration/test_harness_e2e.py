"""Full harness e2e via TrueForge sessions (POST /api/v1/sessions/{id}/turns)."""
import pytest

def test_harness_session_creates():
    import urllib.request, json
    data = json.dumps({"agent": {"name": "patchproof-orchestrator"}}).encode()
    req = urllib.request.Request("http://[::1]:8790/api/v1/sessions", data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read())
        assert "data" in body
        assert body["data"]["agent"]["name"] == "patchproof-orchestrator"
