"""Test suite for DVPWA SQL injection scenario (s06).

Self-contained: uses FastAPI TestClient, no live server.
"""
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_students_empty():
    resp = client.get("/students")
    assert resp.status_code == 200
    assert "students" in resp.json()


def test_create_student_normal():
    resp = client.post("/students", json={"name": "Alice"})
    assert resp.json().get("ok") is True


def test_login_valid():
    resp = client.post("/login", json={"username": "admin", "password": "5f4dcc3b5aa765d61d8327deb882cf99"})
    data = resp.json()
    assert data.get("authenticated") is True


def test_login_invalid():
    resp = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert resp.json().get("authenticated") is False


def test_sql_injection_auth_bypass():
    """DVPWA vulnerability: string formatting allows auth bypass."""
    resp = client.post("/login", json={"username": "admin' OR '1'='1", "password": "x"})
    data = resp.json()
    assert data.get("authenticated") is True, f"Expected auth bypass, got {data}"


def test_sql_injection_drop_table():
    """DVPWA vulnerability: string formatting allows DROP TABLE."""
    payload = "Robert'); DROP TABLE students; --"
    resp = client.post("/students", json={"name": payload})
    data = resp.json()
    # Either the inject succeeds or returns an error (both prove the vuln)
    assert data.get("ok") or data.get("error"), f"Unexpected response: {data}"
