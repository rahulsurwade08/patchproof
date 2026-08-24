"""Test suite shared by both pyyaml scenarios (S1 vulnerable, S5 safe).

A patch attempt on S1 must keep these green after bumping pyyaml.
"""

from fastapi.testclient import TestClient

import main


def client():
    return TestClient(main.app)


def test_health():
    assert client().get("/health").json() == {"status": "ok"}


def test_valid_yaml_loads():
    resp = client().post("/config", content=b"key: value\n",
                         headers={"Content-Type": "application/yaml"})
    assert resp.status_code == 200
    assert resp.json()["loaded"] is True
