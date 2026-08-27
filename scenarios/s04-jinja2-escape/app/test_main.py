"""Test suite for Jinja2 sandbox escape scenario (s04).

Self-contained: uses FastAPI TestClient (in-process ASGI), no live server.
Runs under: python -m pytest test_main.py -q
"""
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_render_safe():
    resp = client.post("/render", json={"template": "Hello {{ name }}", "context": {"name": "world"}})
    assert resp.json()["rendered"] == "Hello world"


def test_render_fmt_normal():
    resp = client.post("/render", json={"template": '{{ "Hello {}" | fmt("world") }}'})
    assert resp.json()["rendered"] == "Hello world"


def test_render_sandbox_blocks_dunder():
    resp = client.post("/render", json={"template": "{{ ''.__class__ }}"})
    data = resp.json()
    assert "error" in data or data.get("rendered", "") == ""


def test_sandbox_escape_via_fmt_filter():
    """CVE-2024-56326: fmt filter calls .format() in native Python, leaking __class__."""
    resp = client.post("/render", json={"template": '{{ "{0.__class__.__mro__}" | fmt("x") }}'})
    data = resp.json()
    rendered = data.get("rendered", "")
    error = data.get("error", "")
    assert "<class" in rendered and "object" in rendered, (
        f"Expected MRO leak, got rendered={rendered!r} error={error!r}"
    )


def test_config_endpoint():
    resp = client.post("/config", json={"template": "Hello"})
    assert resp.json()["result"] == "Hello"
